package blacklist_watcher

import (
	"github.com/coredns/caddy"
	"github.com/coredns/caddy/caddyfile"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func init() { plugin.Register("blacklist_watcher", setup) }

// setup is the function that gets called when the config parser see the token "blacklist_watcher".
func setup(c *caddy.Controller) error {
	bw, err := parseBW(c)
	if err != nil {
		return plugin.Error("blacklist_watcher", err)
	}

	// check postgres configs
	if len(bw.pgHost) < 1 || len(bw.pgUser) < 1 || len(bw.pgPassword) < 1 || len(bw.pgDB) < 1 {
		return plugin.Error("blacklist_watcher", errors.New("pg-host & pg-user & pg-db are required!"))
	}

	if bw.pgSSL {
		if len(bw.pgSSLMode) < 1 {
			return plugin.Error("blacklist_watcher", errors.New("pg-ssl-mode is required when pg-ssl is enabled!"))
		}
		if bw.pgSSLMode != "disable" && bw.pgSSLMode != "require" && bw.pgSSLMode != "verify-ca" && bw.pgSSLMode != "verify-full" {
			return plugin.Error("blacklist_watcher", errors.New("pg-ssl-mode must be one of disable, require, verify-ca, verify-full!"))
		}
		if (bw.pgSSLMode == "verify-ca" || bw.pgSSLMode == "verify-full") && len(bw.pgSSLRootCert) < 1 {
			return plugin.Error("blacklist_watcher", errors.New("pg-ssl-root-cert is required when pg-ssl-mode is verify-ca or verify-full!"))
		}
	}

	// check required params
	if len(bw.dns2check) < 1 {
		return plugin.Error("blacklist_watcher", errors.New("dns-to-check is required!"))
	}

	c.OnStartup(func() error {
		return bw.OnStartup()
	})
	c.OnShutdown(bw.OnShutdown)

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		bw.Next = next
		return bw
	})

	return nil
}

// OnStartup starts a goroutines for all clients.
func (bw *BlacklistWatcher) OnStartup() (err error) {
	// Initialize database connection
	err = bw.initDBConnection()
	if err != nil {
		bw.logger.WithError(err).Error("Failed to initialize database connection")
		return err
	}
	return nil
}

// OnShutdown stops all configured clients.
func (bw *BlacklistWatcher) OnShutdown() error {
	// Close database connection pool
	bw.closeDBConnection()
	bw.logger.Info("Database connection pool closed")
	return nil
}

func parseBW(c *caddy.Controller) (*BlacklistWatcher, error) {
	var (
		bw  *BlacklistWatcher
		err error
		i   int
	)
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++
		bw, err = parseStanza(&c.Dispenser)
		if err != nil {
			return nil, err
		}
	}

	return bw, nil
}

func parseStanza(c *caddyfile.Dispenser) (*BlacklistWatcher, error) {
	bw := New()

	for c.NextBlock() {
		err := parseValue(strings.ToLower(c.Val()), bw, c)
		if err != nil {
			return nil, err
		}
	}
	return bw, nil
}

func parseValue(v string, bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	switch v {
	case "dns-to-check":
		return parseDns2Check(bw, c)
	case "dns-timeout":
		return parseDnsTimeout(bw, c)
	case "sanction-search":
		return parseSanctionSearch(bw, c)
	case "ban-search":
		return parseBanSearch(bw, c)
	case "pg-host":
		return parsePgHost(bw, c)
	case "pg-port":
		return parsePgPort(bw, c)
	case "pg-user":
		return parsePgUser(bw, c)
	case "pg-password":
		return parsePgPassword(bw, c)
	case "pg-db":
		return parsePgDB(bw, c)
	case "pg-schema":
		return parsePgSchema(bw, c)
	case "pg-ssl":
		return parsePgSSL(bw, c)
	case "pg-ssl-mode":
		return parsePgSSLMode(bw, c)
	case "pg-ssl-root-cert":
		return parsePgSSLRootCert(bw, c)
	case "additional-tags":
		return parseAdditionalTags(bw, c)
	case "ban-tag":
		return parseBanTag(bw, c)
	case "sanction-tag":
		return parseSanctionTag(bw, c)
	case "sanction-buffer-size":
		return parseSanctionListBufferSize(bw, c)
	case "ban-buffer-size":
		return parseBanListBufferSize(bw, c)
	case "log-level":
		return parseLogLevel(bw, c)
	default:
		return errors.Errorf("unknown property %v", v)
	}
}

func parseDns2Check(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return errors.New("dns-to-check requires at least one DNS server address")
	}

	for _, arg := range args {
		if arg == "" {
			return errors.New("dns-to-check: empty DNS server address")
		}
		ip, err := net.ResolveUDPAddr("udp", arg)
		if err != nil {
			return errors.Errorf("dns-to-check: invalid DNS server address '%s': %v", arg, err)
		}
		bw.dns2check = append(bw.dns2check, ip)
	}
	return nil
}

func parseDnsTimeout(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}

	timeoutSeconds, err := strconv.Atoi(c.Val())
	if err != nil {
		return errors.Errorf("dns-timeout: invalid timeout value '%s', must be an integer (seconds)", c.Val())
	}

	if timeoutSeconds <= 0 {
		return errors.New("dns-timeout must be greater than 0 seconds")
	}

	if timeoutSeconds > 300 {
		return errors.New("dns-timeout too large (max 300 seconds / 5 minutes)")
	}

	bw.dnsTimeout = time.Duration(timeoutSeconds) * time.Second

	// Update the DNS client with new timeout
	bw.dnsClient = &dns.Client{
		Timeout:      bw.dnsTimeout,
		ReadTimeout:  bw.dnsTimeout,
		WriteTimeout: bw.dnsTimeout,
	}

	return nil
}

func parseSanctionSearch(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return errors.New("sanction-search requires at least one search parameter")
	}

	for _, arg := range args {
		if arg == "" {
			return errors.New("sanction-search: empty search parameter")
		}
		if len(arg) > 255 {
			return errors.New("sanction-search: parameter too long (max 255 characters)")
		}
		bw.sanctionSearchParams = append(bw.sanctionSearchParams, arg)
	}
	return nil
}

func parseBanSearch(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return errors.New("ban-search requires at least one search parameter")
	}

	for _, arg := range args {
		if arg == "" {
			return errors.New("ban-search: empty search parameter")
		}
		if len(arg) > 255 {
			return errors.New("ban-search: parameter too long (max 255 characters)")
		}
		bw.banSearchParams = append(bw.banSearchParams, arg)
	}
	return nil
}

func parseSanctionListBufferSize(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	var err error
	bw.sanctionListBufferSize, err = parsePositiveInt(c)
	return err
}

func parseBanListBufferSize(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	var err error
	bw.banListBufferSize, err = parsePositiveInt(c)
	return err
}

func parseLogLevel(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	level := strings.ToLower(c.Val())

	switch level {
	case "debug":
		bw.logger.Logger.SetLevel(logrus.DebugLevel)
	case "info":
		bw.logger.Logger.SetLevel(logrus.InfoLevel)
	case "warn", "warning":
		bw.logger.Logger.SetLevel(logrus.WarnLevel)
	case "error":
		bw.logger.Logger.SetLevel(logrus.ErrorLevel)
	case "fatal":
		bw.logger.Logger.SetLevel(logrus.FatalLevel)
	default:
		return errors.Errorf("invalid log level: %s (valid: debug, info, warn, error, fatal)", level)
	}

	bw.logLevel = level
	return nil
}

func parsePgHost(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	bw.pgHost = c.Val()
	return nil
}

func parsePgPort(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	var err error
	bw.pgPort, err = parsePositiveInt(c)
	return err
}

func parsePgUser(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	bw.pgUser = c.Val()
	return nil
}

func parsePgPassword(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	bw.pgPassword = c.Val()
	return nil
}

func parsePgDB(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	bw.pgDB = c.Val()
	return nil
}

func parsePgSchema(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	bw.pgSchema = c.Val()
	return nil
}

func parsePgSSL(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	val := strings.ToLower(c.Val())
	if val == "true" {
		bw.pgSSL = true
	} else if val == "false" {
		bw.pgSSL = false
	} else {
		return errors.New("pg-ssl must be either true or false")
	}
	return nil
}

func parsePgSSLMode(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	bw.pgSSLMode = c.Val()
	return nil
}

func parsePgSSLRootCert(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	v := c.Val()
	if (bw.pgSSLMode == "verify-ca" || bw.pgSSLMode == "verify-full") && (len(bw.pgSSLRootCert) < 1 || !filepath.IsAbs(v)) {
		return errors.New("pg-ssl-root-cert must be an absolute path when pg-ssl-mode is verify-ca or verify-full!")
	}
	bw.pgSSLRootCert = v
	return nil
}

func parseAdditionalTags(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr()
	}

	if bw.additionalTags == nil {
		bw.additionalTags = make(map[string]string)
	}

	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			return errors.Errorf("invalid additional-tag %q, expected key=value", arg)
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" {
			return errors.Errorf("invalid additional-tag %q: empty key", arg)
		}
		bw.additionalTags[key] = val
	}
	return nil
}

func parseBanTag(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	bw.banTag = c.Val()
	return nil
}

func parseSanctionTag(bw *BlacklistWatcher, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	bw.sanctionTag = c.Val()
	return nil
}

func parsePositiveInt(c *caddyfile.Dispenser) (int, error) {
	if !c.NextArg() {
		return -1, c.ArgErr()
	}
	v := c.Val()
	num, err := strconv.Atoi(v)
	if err != nil {
		return -1, c.ArgErr()
	}
	if num <= 0 {
		return -1, errors.New("value must be greater than 0")
	}
	if num > 100000 {
		return -1, errors.New("value too large (max 100000)")
	}
	return num, nil
}
