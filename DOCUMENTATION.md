# CoreDNS Blacklist Watcher Plugin

## Table of Contents
1. [Overview](#overview)
2. [How It Works](#how-it-works)
3. [Architecture](#architecture)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Database Schema](#database-schema)
7. [Usage Examples](#usage-examples)
8. [Security Considerations](#security-considerations)
9. [Performance Tuning](#performance-tuning)
10. [Troubleshooting](#troubleshooting)

---

## Overview

**Blacklist Watcher** is a CoreDNS plugin that monitors DNS queries and automatically detects banned or sanctioned domains by querying upstream DNS servers and analyzing their responses. When specific patterns are found in DNS responses, the plugin categorizes domains and stores them in a PostgreSQL database with customizable tags for further analysis and action.

### Key Features

- **Automatic Detection**: Monitors DNS queries in real-time and detects banned/sanctioned domains based on configurable search patterns
- **PostgreSQL Integration**: Stores detected domains with JSONB tags for flexible querying and analysis
- **Buffer System**: Uses in-memory buffering to reduce database writes and improve performance
- **Concurrency Control**: Built-in semaphore limits concurrent DNS queries to prevent resource exhaustion
- **Thread-Safe**: Proper mutex handling prevents race conditions in concurrent environments
- **Customizable Tagging**: Supports custom tags to categorize and label detected domains
- **SQL Injection Prevention**: Validates and sanitizes all user inputs to prevent security vulnerabilities

---

## How It Works

### High-Level Workflow

```
DNS Query → CoreDNS → Blacklist Watcher Plugin → [Checks Upstream DNS Servers]
                                                           ↓
                                    [Analyzes Responses for Ban/Sanction Patterns]
                                                           ↓
                                           [Adds to In-Memory Buffer]
                                                           ↓
                                    [Flushes to PostgreSQL When Buffer is Full]
```

### Detailed Process

1. **DNS Query Interception**: When a DNS query passes through CoreDNS, the Blacklist Watcher plugin intercepts it (non-blocking)

2. **Upstream Query**: The plugin sends the same DNS query to configured upstream DNS servers (e.g., `78.157.42.101:53`)

3. **Response Analysis**: For each response, the plugin searches for configured patterns:
   - **Ban Patterns**: e.g., `10.10.34.35` (IP address indicating a banned domain)
   - **Sanction Patterns**: e.g., `develop.403`, `electro` (keywords in DNS responses)

4. **Domain Buffering**: If a pattern matches:
   - Extract the domain name from the DNS query
   - Add it to an in-memory buffer (separate buffers for ban/sanction)
   - Check buffer size against configured limit

5. **Database Flush**: When buffer reaches configured size (e.g., 10 domains):
   - Open database transaction
   - Insert all buffered domains with tags into PostgreSQL
   - Clear the buffer
   - Log the operation

6. **Concurrent Processing**: All upstream queries run in background goroutines with:
   - Semaphore limiting max concurrent requests (default: 1000)
   - Mutex-protected buffer access
   - Automatic resource cleanup

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     CoreDNS Server                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │      Blacklist Watcher Plugin                       │   │
│  │                                                       │   │
│  │  ┌──────────────┐  ┌──────────────┐                │   │
│  │  │ Ban Buffer   │  │Sanction Buf  │                │   │
│  │  │  (mutex)     │  │   (mutex)    │                │   │
│  │  └──────┬───────┘  └──────┬───────┘                │   │
│  │         │                  │                         │   │
│  │  ┌──────▼──────────────────▼───────┐               │   │
│  │  │   Database Flush Manager        │               │   │
│  │  └──────────────┬──────────────────┘               │   │
│  │                 │                                    │   │
│  │  ┌──────────────▼──────────────┐                   │   │
│  │  │   Query Semaphore (1000)    │                   │   │
│  │  └──────────────┬──────────────┘                   │   │
│  │                 │                                    │   │
│  │  ┌──────────────▼──────────────┐                   │   │
│  │  │  DNS Query Dispatcher       │                   │   │
│  │  └─────────────────────────────┘                   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   [DNS Server 1]  [DNS Server 2]  [DNS Server 3]
   78.157.42.101   10.202.10.202   (configurable)

        │                │                │
        └────────────────┼────────────────┘
                         ▼
              ┌──────────────────────┐
              │  PostgreSQL Database  │
              │                       │
              │  ┌─────────────────┐ │
              │  │  domains table  │ │
              │  │  - id           │ │
              │  │  - domain       │ │
              │  │  - tags (JSONB) │ │
              │  │  - detected_at  │ │
              │  │  - created_at   │ │
              │  └─────────────────┘ │
              └──────────────────────┘
```

### Thread Safety

The plugin uses the following synchronization mechanisms:

1. **Mutex Locks**: `banMu` and `sanctionMu` protect buffer access
2. **Semaphore Channel**: `querySem` limits concurrent DNS queries
3. **Atomic Operations**: Check-and-add operations are performed atomically within locks

---

## Installation

### Prerequisites

- Go 1.20 or later
- CoreDNS source code
- PostgreSQL 12 or later

### Build Steps

1. **Clone CoreDNS**:
   ```bash
   git clone https://github.com/coredns/coredns.git
   cd coredns
   ```

2. **Add Plugin to CoreDNS**:

   Edit `plugin.cfg` and add:
   ```
   blacklist_watcher:github.com/MrMohebi/coredns_blacklist_watcher
   ```

3. **Update Dependencies**:
   ```bash
   go get github.com/MrMohebi/coredns_blacklist_watcher
   go mod tidy
   ```

4. **Build CoreDNS**:
   ```bash
   make
   ```

5. **Verify Installation**:
   ```bash
   ./coredns -plugins | grep blacklist_watcher
   ```

---

## Configuration

### Corefile Example

```corefile
. {
    # Other plugins (e.g., cache, forward, etc.)

    blacklist_watcher {
        # Required: DNS servers to query for detection
        dns-to-check 78.157.42.101:53 10.202.10.202:53

        # Optional: DNS query timeout in seconds (default: 5, range: 1-300)
        dns-timeout 10

        # Required: Patterns to search for in DNS responses
        sanction-search develop.403 electro
        ban-search 10.10.34.35

        # Required: PostgreSQL connection parameters
        pg-host 127.0.0.1
        pg-port 5432
        pg-user postgres
        pg-password your_secure_password
        pg-db blacklist_db
        pg-schema public

        # Optional: PostgreSQL SSL configuration
        pg-ssl false
        # pg-ssl-mode verify-ca
        # pg-ssl-root-cert /path/to/ca-cert.pem

        # Optional: Custom tags (key=value format)
        additional-tags server=dns1 location=us-west environment=production

        # Optional: Custom tag values for ban/sanction types
        ban-tag BLOCKED
        sanction-tag SANCTIONED

        # Optional: Buffer sizes (flush to DB when reached)
        sanction-buffer-size 10
        ban-buffer-size 10

        # Optional: Logging level (debug, info, warn, error, fatal)
        log-level info
    }
}
```

### Configuration Parameters

#### Required Parameters

| Parameter         | Type      | Description                            | Example                             |
|-------------------|-----------|----------------------------------------|-------------------------------------|
| `dns-to-check`    | addresses | List of upstream DNS servers to query  | `78.157.42.101:53 10.202.10.202:53` |
| `sanction-search` | strings   | Patterns indicating sanctioned domains | `develop.403 electro`               |
| `ban-search`      | strings   | Patterns indicating banned domains     | `10.10.34.35`                       |
| `pg-host`         | string    | PostgreSQL server hostname/IP          | `127.0.0.1`                         |
| `pg-user`         | string    | PostgreSQL username                    | `postgres`                          |
| `pg-password`     | string    | PostgreSQL password                    | `your_password`                     |
| `pg-db`           | string    | PostgreSQL database name               | `blacklist_db`                      |

#### Optional Parameters

| Parameter              | Type            | Default    | Description                                            |
|------------------------|-----------------|------------|--------------------------------------------------------|
| `dns-timeout`          | integer         | `5`        | DNS query timeout in seconds (range: 1-300)            |
| `pg-port`              | integer         | `5432`     | PostgreSQL server port                                 |
| `pg-schema`            | string          | `public`   | PostgreSQL schema name                                 |
| `pg-ssl`               | boolean         | `false`    | Enable PostgreSQL SSL connection                       |
| `pg-ssl-mode`          | string          | `require`  | SSL mode (disable, require, verify-ca, verify-full)    |
| `pg-ssl-root-cert`     | path            | -          | Path to SSL root certificate                           |
| `additional-tags`      | key=value pairs | -          | Custom tags to attach to all detected domains          |
| `ban-tag`              | string          | `BAN`      | Tag value for banned domains                           |
| `sanction-tag`         | string          | `SANCTION` | Tag value for sanctioned domains                       |
| `sanction-buffer-size` | integer         | `10`       | Number of sanctioned domains to buffer before DB flush |
| `ban-buffer-size`      | integer         | `10`       | Number of banned domains to buffer before DB flush     |
| `log-level`            | string          | `info`     | Logging verbosity level                                |

#### Validation Rules

- **DNS Timeout**: Must be > 0 and ≤ 300 seconds (5 minutes)
- **Buffer Sizes**: Must be > 0 and ≤ 100,000
- **DNS Addresses**: Must be valid UDP addresses with port
- **Search Patterns**: Must be non-empty and ≤ 255 characters
- **Schema Name**: Must match `^[a-zA-Z_][a-zA-Z0-9_]*$` (alphanumeric + underscore)
- **Additional Tags**: Must be in `key=value` format with non-empty keys

---

## Database Schema

### Table: `domains`

```sql
CREATE TABLE public.domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    tags JSONB,
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_domains_domain ON public.domains(domain);
CREATE INDEX idx_domains_tags ON public.domains USING GIN(tags);
```

### Field Descriptions

| Field         | Type         | Description                                             |
|---------------|--------------|---------------------------------------------------------|
| `id`          | SERIAL       | Auto-incrementing primary key                           |
| `domain`      | VARCHAR(255) | The detected domain name (unique constraint)            |
| `tags`        | JSONB        | JSON object containing tags (`type`, custom tags, etc.) |
| `detected_at` | TIMESTAMP    | When the domain was last detected                       |
| `created_at`  | TIMESTAMP    | When the domain was first inserted                      |

### Tags Structure

The `tags` JSONB field contains:
```json
{
  "type": "BAN",  // or "SANCTION"
  "server": "dns1",  // from additional-tags
  "location": "us-west",  // from additional-tags
  "environment": "production"  // from additional-tags
}
```

### Example Queries

**Get all banned domains**:
```sql
SELECT domain, detected_at
FROM public.domains
WHERE tags->>'type' = 'BAN'
ORDER BY detected_at DESC;
```

**Get sanctioned domains from specific server**:
```sql
SELECT domain, tags
FROM public.domains
WHERE tags->>'type' = 'SANCTION'
  AND tags->>'server' = 'dns1';
```

**Count domains by type**:
```sql
SELECT tags->>'type' AS type, COUNT(*)
FROM public.domains
GROUP BY tags->>'type';
```

**Recently detected domains (last 24 hours)**:
```sql
SELECT domain, tags->>'type' AS type, detected_at
FROM public.domains
WHERE detected_at > NOW() - INTERVAL '24 hours'
ORDER BY detected_at DESC;
```

---

## Usage Examples

### Example 1: Basic Banned Domain Detection

**Scenario**: Detect domains that resolve to a specific ban page IP

**Configuration**:
```corefile
blacklist_watcher {
    dns-to-check 8.8.8.8:53
    ban-search 10.10.34.35

    pg-host localhost
    pg-user postgres
    pg-password secret
    pg-db monitoring_db

    ban-buffer-size 5
}
```

**Behavior**:
- Query `banned-site.com` → DNS responds with `10.10.34.35`
- Plugin detects pattern match → Adds to ban buffer
- After 5 domains → Flushes to database with `{"type": "BAN"}`

### Example 2: Sanction Detection with Custom Tags

**Scenario**: Monitor multiple DNS servers with geographic tagging

**Configuration**:
```corefile
blacklist_watcher {
    dns-to-check 78.157.42.101:53 10.202.10.202:53

    sanction-search develop.403 restricted
    ban-search 10.10.34.35 192.168.1.100

    additional-tags datacenter=us-east region=north-america
    sanction-tag CENSORED
    ban-tag BLOCKED

    pg-host db.example.com
    pg-port 5432
    pg-user monitor_user
    pg-password complex_password
    pg-db geo_monitoring

    log-level debug
}
```

**Behavior**:
- Query `censored-news.com` → DNS response contains `develop.403`
- Plugin adds to sanction buffer with tags: `{"type": "CENSORED", "datacenter": "us-east", "region": "north-america"}`
- Flush to database when buffer full

### Example 3: High-Volume Production Setup

**Scenario**: Large DNS server handling millions of queries

**Configuration**:
```corefile
blacklist_watcher {
    dns-to-check 1.1.1.1:53 8.8.8.8:53 9.9.9.9:53

    sanction-search filtered blocked censored
    ban-search 0.0.0.0 127.0.0.1 10.0.0.0

    pg-host db-primary.prod.internal
    pg-port 5432
    pg-user blacklist_app
    pg-password $SECURE_PASSWORD
    pg-db blacklist_production
    pg-schema monitoring

    pg-ssl true
    pg-ssl-mode verify-full
    pg-ssl-root-cert /etc/ssl/certs/ca-bundle.crt

    additional-tags cluster=prod-us pod=dns-03 version=2.1.0

    # Higher buffer sizes to reduce DB writes
    sanction-buffer-size 100
    ban-buffer-size 100

    log-level info
}
```

---

## Security Considerations

### SQL Injection Prevention

**Vulnerability**: Schema names were directly interpolated into SQL queries

**Fix**: All database identifiers are now validated and properly quoted:
```go
// Validate schema name
func sanitizeIdentifier(identifier string) error {
    matched, _ := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_]*$`, identifier)
    if !matched {
        return fmt.Errorf("invalid identifier")
    }
    return nil
}

// Quote identifier for safe SQL construction
func quoteIdentifier(identifier string) string {
    escaped := strings.ReplaceAll(identifier, `"`, `""`)
    return `"` + escaped + `"`
}
```

**Recommendation**:
- Always use the default `public` schema or alphanumeric schema names
- Never allow user input to directly control schema names
- Use PostgreSQL parameterized queries for all data values (already implemented)

### Password Storage

**Warning**: Passwords in Corefile are stored in plaintext!

**Recommendations**:
1. Use environment variables: `pg-password $POSTGRES_PASSWORD`
2. Restrict Corefile permissions: `chmod 600 /etc/coredns/Corefile`
3. Use PostgreSQL `.pgpass` file for passwordless auth
4. Consider using certificate-based authentication with `pg-ssl`

### SSL/TLS Configuration

For production environments, **always** enable PostgreSQL SSL:

```corefile
pg-ssl true
pg-ssl-mode verify-full  # Strongest: validates certificate and hostname
pg-ssl-root-cert /path/to/root.crt
```

SSL Modes:
- `disable`: No encryption (insecure)
- `require`: Encryption but no certificate validation
- `verify-ca`: Validates certificate authority
- `verify-full`: Validates CA and hostname (recommended)

### Network Security

- **Firewall Rules**: Restrict PostgreSQL port (5432) to authorized hosts only
- **DNS Servers**: Only query trusted DNS servers; malicious responses could trigger false positives
- **Rate Limiting**: The semaphore (max 1000 concurrent queries) prevents resource exhaustion

---

## Performance Tuning

### Buffer Size Optimization

**Trade-offs**:
- **Small Buffers** (5-10): More frequent DB writes, lower memory usage, faster detection visibility
- **Large Buffers** (100-1000): Fewer DB writes, higher throughput, delayed visibility

**Recommendations**:
- Development: 5-10
- Production (low traffic): 10-50
- Production (high traffic): 50-200
- Never exceed 10,000 (memory/batch insert limits)

### DNS Timeout Optimization

**Trade-offs**:
- **Short Timeout** (1-5 seconds): Faster failure detection, may miss slow servers, lower resource usage
- **Medium Timeout** (5-15 seconds): Balanced approach, works for most networks
- **Long Timeout** (15-60 seconds): Accommodates slow/distant servers, higher resource usage, delayed responses

**Recommendations by Network Type**:
- **Local Network** (LAN): `dns-timeout 2`
- **Same Region** (low latency): `dns-timeout 5` (default)
- **Cross-Region** (moderate latency): `dns-timeout 10`
- **International** (high latency): `dns-timeout 20`
- **Satellite/Mobile** (very high latency): `dns-timeout 30`

**Example Configurations**:

Fast local DNS:
```corefile
dns-to-check 192.168.1.1:53
dns-timeout 3
```

International DNS monitoring:
```corefile
dns-to-check 78.157.42.101:53 8.8.8.8:53
dns-timeout 20
```

**Warning**: Timeouts > 30 seconds may cause goroutine accumulation under high load!

### Concurrency Limits

The semaphore limit is hardcoded to 1000 concurrent goroutines. Adjust in code:

```go
querySem: make(chan struct{}, 1000),  // Increase for higher throughput
```

**Warning**: Higher limits consume more memory and database connections!

### Database Optimization

**Indexes**:
```sql
-- Already created automatically:
CREATE INDEX idx_domains_domain ON domains(domain);
CREATE INDEX idx_domains_tags ON domains USING GIN(tags);

-- Additional indexes for common queries:
CREATE INDEX idx_detected_at ON domains(detected_at DESC);
CREATE INDEX idx_type ON domains((tags->>'type'));
```

**Connection Pooling**:
Consider using a connection pool for high-traffic scenarios:
```go
// Future enhancement: Replace pgx.Conn with pgxpool.Pool
pgConnection *pgxpool.Pool
```

### Logging Performance

**Impact**: Debug logging can significantly reduce performance

**Recommendations**:
- Production: `log-level info` or `log-level warn`
- Development: `log-level debug`
- Troubleshooting: Temporarily enable `debug`, then revert

---

## Troubleshooting

### Common Issues

#### 1. "database connection not initialized"

**Cause**: PostgreSQL connection failed during startup

**Solutions**:
- Check PostgreSQL server is running: `systemctl status postgresql`
- Verify connection parameters (host, port, user, password, database)
- Check firewall rules: `telnet pg-host 5432`
- Review CoreDNS logs: `journalctl -u coredns -f`

#### 2. "too many concurrent DNS queries"

**Cause**: More than 1000 DNS queries/second

**Solutions**:
- Increase semaphore limit in code (recompile required)
- Add more DNS servers to `dns-to-check`
- Optimize upstream DNS server response times
- Consider horizontal scaling (multiple CoreDNS instances)

#### 3. "invalid schema name"

**Cause**: Schema name contains invalid characters

**Solutions**:
- Use alphanumeric + underscore only: `my_schema_123`
- Avoid special characters: `public-prod` (invalid)
- Start with letter or underscore: `_temp` (valid), `9schema` (invalid)

#### 4. DNS timeout errors

**Cause**: DNS queries to upstream servers are timing out

**Symptoms**:
- Error logs showing: `Error when asking DNS server (check timeout if needed): timeout=5s`
- `i/o timeout` errors in logs
- No domains being detected despite traffic

**Solutions**:
- Increase DNS timeout: `dns-timeout 10` (or higher for slow servers)
- For high-latency servers (international): `dns-timeout 30`
- Check network connectivity: `ping DNS_SERVER_IP`
- Test DNS server manually: `dig @SERVER_IP example.com +time=5`
- Verify DNS servers are not rate-limiting your queries

#### 5. No domains detected

**Cause**: Search patterns don't match DNS responses

**Solutions**:
- Enable debug logging: `log-level debug`
- Manually query upstream DNS: `dig @78.157.42.101 example.com`
- Verify patterns match response format
- Check that `dns-to-check` servers are accessible
- Increase DNS timeout if servers are slow: `dns-timeout 15`

#### 6. Slow performance / high memory

**Cause**: Buffer sizes too large or too many concurrent queries

**Solutions**:
- Reduce buffer sizes: `ban-buffer-size 10`
- Lower log level: `log-level warn`
- Add database indexes
- Monitor goroutine count: `runtime.NumGoroutine()`

### Debug Logging

Enable detailed logging:
```corefile
blacklist_watcher {
    log-level debug
    # ... other config
}
```

Sample debug output:
```
[INFO] Successfully connected to PostgreSQL database
[DEBUG] No question URLs in DNS request
[INFO] URLs were banned: example.com (server: 78.157.42.101:53)
[DEBUG] URL already in banned cache: example.com
[INFO] Flushed banned domains to database: count=10
```

---

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Submit a pull request

---

## Support

For issues, questions, or feature requests, please open an issue on GitHub:
https://github.com/MrMohebi/coredns_blacklist_watcher/issues

---

**Last Updated**: 2025-12-28
**Author**: MrMohebi
