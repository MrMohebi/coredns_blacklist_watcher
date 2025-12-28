package blacklist_watcher

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin"
	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BlacklistWatcher is a coredns plugin to write banned and sanctioned domains to PostgreSQL.
type BlacklistWatcher struct {
	dns2check            []net.Addr
	sanctionSearchParams []string
	banSearchParams      []string

	pgConnection *pgx.Conn

	pgHost     string
	pgPort     int
	pgUser     string
	pgPassword string
	pgDB       string
	pgSchema   string

	pgSSL         bool
	pgSSLMode     string
	pgSSLRootCert string

	additionalTags map[string]string
	banTag         string
	sanctionTag    string

	banMu        sync.Mutex
	sanctionMu   sync.Mutex
	sanctionList []string
	banList      []string

	banListBufferSize      int
	sanctionListBufferSize int

	logger   *logrus.Logger
	logLevel string

	// DNS query timeout in seconds
	dnsTimeout time.Duration

	// DNS client for queries
	dnsClient *dns.Client

	// Semaphore to limit concurrent DNS queries
	querySem chan struct{}

	Next plugin.Handler
}

func New() *BlacklistWatcher {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logger.SetLevel(logrus.InfoLevel)

	// Default DNS timeout: 5 seconds
	dnsTimeout := 5 * time.Second

	return &BlacklistWatcher{
		banListBufferSize:      10,
		sanctionListBufferSize: 10,
		pgPort:                 5432,
		pgSchema:               "public",
		pgSSL:                  false,
		pgSSLMode:              "require",
		pgSSLRootCert:          "",
		banTag:                 "BAN",
		sanctionTag:            "SANCTION",
		additionalTags:         make(map[string]string),
		logger:                 logger,
		logLevel:               "info",
		dnsTimeout:             dnsTimeout,
		dnsClient: &dns.Client{
			Timeout:      dnsTimeout,
			ReadTimeout:  dnsTimeout,
			WriteTimeout: dnsTimeout,
		},
		querySem: make(chan struct{}, 1000), // Limit to 1000 concurrent queries
	}
}

// Name implements the Handler interface.
func (bw *BlacklistWatcher) Name() string { return "blacklist_watcher" }

// ServeDNS implements the plugin.Handler interface. This method gets called when blacklist_watcher is used
// in a Server.
func (bw *BlacklistWatcher) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	req := r.Copy()

	// Use semaphore to limit concurrent goroutines
	select {
	case bw.querySem <- struct{}{}:
		go func() {
			defer func() { <-bw.querySem }()
			askFromDnsServers(bw, req)
		}()
	default:
		// Too many concurrent queries, log and skip
		bw.logger.Warn("Too many concurrent DNS queries, skipping blacklist check")
	}

	// Call next plugin (if any).
	return plugin.NextOrFailure(bw.Name(), bw.Next, ctx, w, r)
}

func askFromDnsServers(bw *BlacklistWatcher, req *dns.Msg) {
	urls := getQuestionUrls(req)
	if len(urls) == 0 {
		bw.logger.Debug("No question URLs in DNS request")
		return
	}

	for _, server := range bw.dns2check {
		// Use the configured DNS client with timeout
		resp, _, err := bw.dnsClient.Exchange(req, server.String())
		if err != nil {
			bw.logger.WithError(err).WithFields(logrus.Fields{
				"urls":    strings.Join(urls, " "),
				"server":  server.String(),
				"timeout": bw.dnsTimeout,
			}).Error("Error when asking DNS server (check timeout if needed)")
			continue
		}

		// Check if response is nil
		if resp == nil {
			bw.logger.WithFields(logrus.Fields{
				"urls":   strings.Join(urls, " "),
				"server": server.String(),
			}).Warn("Received nil response from DNS server")
			continue
		}

		// Check for ban
		banned, err := checkBan(bw, resp)
		if err != nil {
			bw.logger.WithError(err).WithFields(logrus.Fields{
				"urls": strings.Join(urls, " "),
			}).Error("Error when checking for ban")
			continue
		}

		if banned {
			bw.logger.WithFields(logrus.Fields{
				"urls":   strings.Join(urls, " "),
				"server": server.String(),
			}).Info("URLs were banned")
			break
		}

		// Check for sanction
		sanctioned, err := checkSanction(bw, resp)
		if err != nil {
			bw.logger.WithError(err).WithFields(logrus.Fields{
				"urls": strings.Join(urls, " "),
			}).Error("Error when checking for sanction")
			continue
		}

		if sanctioned {
			bw.logger.WithFields(logrus.Fields{
				"urls":   strings.Join(urls, " "),
				"server": server.String(),
			}).Info("URLs were sanctioned")
			break
		}
	}
}

func checkSanction(bw *BlacklistWatcher, resp *dns.Msg) (bool, error) {
	for _, p := range bw.sanctionSearchParams {
		if strings.Contains(resp.String(), p) {
			urls := getQuestionUrls(resp)
			if len(urls) == 0 {
				return false, fmt.Errorf("no question URLs found in response")
			}

			url := urls[0]
			if url == "" {
				return false, fmt.Errorf("empty domain name")
			}

			// Check and add within the same lock to avoid race condition
			err := addSanctionToListIfNotExists(bw, url)
			if err != nil {
				return true, err
			}

			return true, nil
		}
	}
	return false, nil
}

func checkBan(bw *BlacklistWatcher, resp *dns.Msg) (bool, error) {
	for _, p := range bw.banSearchParams {
		if strings.Contains(resp.String(), p) {
			urls := getQuestionUrls(resp)
			if len(urls) == 0 {
				return false, fmt.Errorf("no question URLs found in response")
			}

			url := urls[0]
			if url == "" {
				return false, fmt.Errorf("empty domain name")
			}

			// Check and add within the same lock to avoid race condition
			err := addBanToListIfNotExists(bw, url)
			if err != nil {
				return true, err
			}

			return true, nil
		}
	}
	return false, nil
}

// addBanToListIfNotExists checks if URL exists and adds it atomically
func addBanToListIfNotExists(bw *BlacklistWatcher, url string) error {
	bw.banMu.Lock()
	defer bw.banMu.Unlock()

	// Check if already in list while holding the lock
	for _, item := range bw.banList {
		if item == url {
			bw.logger.WithField("url", url).Debug("URL already in banned cache")
			return nil
		}
	}

	bw.banList = append(bw.banList, url)
	if len(bw.banList) >= bw.banListBufferSize {
		err := flushBanListToDB(bw)
		if err != nil {
			bw.logger.WithError(err).Error("Failed to flush ban list to database")
			return err
		}
		bw.banList = nil
	}

	return nil
}

// addSanctionToListIfNotExists checks if URL exists and adds it atomically
func addSanctionToListIfNotExists(bw *BlacklistWatcher, url string) error {
	bw.sanctionMu.Lock()
	defer bw.sanctionMu.Unlock()

	// Check if already in list while holding the lock
	for _, item := range bw.sanctionList {
		if item == url {
			bw.logger.WithField("url", url).Debug("URL already in sanctioned cache")
			return nil
		}
	}

	bw.sanctionList = append(bw.sanctionList, url)
	if len(bw.sanctionList) >= bw.sanctionListBufferSize {
		err := flushSanctionListToDB(bw)
		if err != nil {
			bw.logger.WithError(err).Error("Failed to flush sanction list to database")
			return err
		}
		bw.sanctionList = nil
	}

	return nil
}

func flushBanListToDB(bw *BlacklistWatcher) error {
	if bw.pgConnection == nil {
		return fmt.Errorf("database connection not initialized")
	}

	if len(bw.banList) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build tags map
	tags := make(map[string]string)
	for k, v := range bw.additionalTags {
		tags[k] = v
	}
	tags["type"] = bw.banTag

	// Use sanitized schema name
	safeSchema := quoteIdentifier(bw.pgSchema)
	query := fmt.Sprintf(`INSERT INTO %s.domains (domain, tags, detected_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (domain) DO UPDATE SET tags = EXCLUDED.tags, detected_at = EXCLUDED.detected_at`,
		safeSchema)

	for _, domain := range bw.banList {
		if domain == "" {
			continue // Skip empty domains
		}

		_, err := bw.pgConnection.Exec(ctx, query, domain, tags, time.Now())
		if err != nil {
			return fmt.Errorf("failed to insert domain %s: %w", domain, err)
		}
	}

	bw.logger.WithFields(logrus.Fields{
		"count":   len(bw.banList),
		"domains": strings.Join(bw.banList, ", "),
		"tag":     bw.banTag,
	}).Info("Flushed banned domains to database")

	return nil
}

func flushSanctionListToDB(bw *BlacklistWatcher) error {
	if bw.pgConnection == nil {
		return fmt.Errorf("database connection not initialized")
	}

	if len(bw.sanctionList) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build tags map
	tags := make(map[string]string)
	for k, v := range bw.additionalTags {
		tags[k] = v
	}
	tags["type"] = bw.sanctionTag

	// Use sanitized schema name
	safeSchema := quoteIdentifier(bw.pgSchema)
	query := fmt.Sprintf(`INSERT INTO %s.domains (domain, tags, detected_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (domain) DO UPDATE SET tags = EXCLUDED.tags, detected_at = EXCLUDED.detected_at`,
		safeSchema)

	for _, domain := range bw.sanctionList {
		if domain == "" {
			continue // Skip empty domains
		}

		_, err := bw.pgConnection.Exec(ctx, query, domain, tags, time.Now())
		if err != nil {
			return fmt.Errorf("failed to insert domain %s: %w", domain, err)
		}
	}

	bw.logger.WithFields(logrus.Fields{
		"count":   len(bw.sanctionList),
		"domains": strings.Join(bw.sanctionList, ", "),
		"tag":     bw.sanctionTag,
	}).Info("Flushed sanctioned domains to database")

	return nil
}

func getQuestionUrls(msg *dns.Msg) []string {
	var result []string
	if msg == nil {
		return result
	}

	for _, question := range msg.Question {
		result = append(result, strings.TrimSuffix(question.Name, "."))
	}
	return result
}

// sanitizeIdentifier validates PostgreSQL identifiers (schema, table names)
// Only allows alphanumeric characters and underscores to prevent SQL injection
func sanitizeIdentifier(identifier string) error {
	if identifier == "" {
		return fmt.Errorf("identifier cannot be empty")
	}

	// PostgreSQL identifier max length is 63 characters
	if len(identifier) > 63 {
		return fmt.Errorf("identifier too long (max 63 characters)")
	}

	// Only allow alphanumeric and underscores, must start with letter or underscore
	matched, err := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_]*$`, identifier)
	if err != nil {
		return err
	}
	if !matched {
		return fmt.Errorf("identifier '%s' contains invalid characters (only alphanumeric and underscore allowed, must start with letter or underscore)", identifier)
	}

	return nil
}

// quoteIdentifier quotes a PostgreSQL identifier to prevent SQL injection
func quoteIdentifier(identifier string) string {
	// Escape any double quotes in the identifier
	escaped := strings.ReplaceAll(identifier, `"`, `""`)
	return `"` + escaped + `"`
}

// buildConnectionString builds PostgreSQL connection string
func (bw *BlacklistWatcher) buildConnectionString() string {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s",
		bw.pgHost, bw.pgPort, bw.pgUser, bw.pgPassword, bw.pgDB)

	if bw.pgSSL {
		connStr += fmt.Sprintf(" sslmode=%s", bw.pgSSLMode)
		if bw.pgSSLRootCert != "" {
			connStr += fmt.Sprintf(" sslrootcert=%s", bw.pgSSLRootCert)
		}
	} else {
		connStr += " sslmode=disable"
	}

	return connStr
}

// initDBConnection initializes the PostgreSQL connection
func (bw *BlacklistWatcher) initDBConnection() error {
	// Validate schema name before connecting
	if err := sanitizeIdentifier(bw.pgSchema); err != nil {
		return fmt.Errorf("invalid schema name: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	connStr := bw.buildConnectionString()
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test connection
	err = conn.Ping(ctx)
	if err != nil {
		_ = conn.Close(ctx)
		return fmt.Errorf("failed to ping database: %w", err)
	}

	bw.pgConnection = conn

	// Create table if not exists
	err = bw.createTableIfNotExists()
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	bw.logger.Info("Successfully connected to PostgreSQL database")
	return nil
}

// createTableIfNotExists creates the domains table if it doesn't exist
func (bw *BlacklistWatcher) createTableIfNotExists() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use quoted identifier for safety
	safeSchema := quoteIdentifier(bw.pgSchema)

	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s.domains (
			id SERIAL PRIMARY KEY,
			domain VARCHAR(255) UNIQUE NOT NULL,
			tags JSONB,
			detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_domains_domain ON %s.domains(domain);
		CREATE INDEX IF NOT EXISTS idx_domains_tags ON %s.domains USING GIN(tags);
	`, safeSchema, safeSchema, safeSchema)

	_, err := bw.pgConnection.Exec(ctx, query)
	return err
}

// closeDBConnection closes the PostgreSQL connection
func (bw *BlacklistWatcher) closeDBConnection() error {
	if bw.pgConnection != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return bw.pgConnection.Close(ctx)
	}
	return nil
}
