# CoreDNS Blacklist Watcher Plugin

[![Go Report Card](https://goreportcard.com/badge/github.com/MrMohebi/coredns_blacklist_watcher)](https://goreportcard.com/report/github.com/MrMohebi/coredns_blacklist_watcher)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A CoreDNS plugin that automatically detects and records banned or sanctioned domains by analyzing DNS responses from upstream servers and storing them in PostgreSQL with customizable tags.

## 🚀 Features

- ✅ **Automatic Detection**: Real-time monitoring of DNS queries for banned/sanctioned domains
- ✅ **PostgreSQL Integration**: Stores detected domains with JSONB tags for flexible querying
- ✅ **Buffer System**: In-memory buffering reduces database writes and improves performance
- ✅ **Thread-Safe**: Mutex-protected operations prevent race conditions
- ✅ **Concurrency Control**: Built-in semaphore prevents resource exhaustion
- ✅ **Security Hardened**: SQL injection prevention, input validation, and secure connection support
- ✅ **Customizable Tagging**: Add custom metadata to categorize detected domains

## 📋 Quick Start

### Basic Configuration

```corefile
. {
    blacklist_watcher {
        # DNS servers to query for detection
        dns-to-check 78.157.42.101:53 10.202.10.202:53

        # Optional: DNS query timeout in seconds (default: 5)
        dns-timeout 10

        # Detection patterns
        sanction-search develop.403 electro
        ban-search 10.10.34.35

        # PostgreSQL connection
        pg-host 127.0.0.1
        pg-port 5432
        pg-user postgres
        pg-password yourpassword
        pg-db blacklist_db
        pg-schema public

        # Optional: Custom tags
        additional-tags server=dns1 location=us-west

        # Optional: Buffer configuration
        sanction-buffer-size 10
        ban-buffer-size 10

        # Optional: Logging
        log-level info
    }
}
```

## 📊 Database Schema

The plugin automatically creates a `domains` table:

```sql
CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    tags JSONB,  -- {"type": "BAN", "server": "dns1", ...}
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

### Example Queries

**Get all banned domains:**
```sql
SELECT domain, detected_at
FROM domains
WHERE tags->>'type' = 'BAN'
ORDER BY detected_at DESC;
```

**Count by type:**
```sql
SELECT tags->>'type' AS type, COUNT(*)
FROM domains
GROUP BY tags->>'type';
```

## 🔧 Configuration Options

### Required Parameters

| Parameter         | Description                     | Example                  |
|-------------------|---------------------------------|--------------------------|
| `dns-to-check`    | Upstream DNS servers to query   | `8.8.8.8:53 1.1.1.1:53`  |
| `sanction-search` | Patterns for sanctioned domains | `develop.403 restricted` |
| `ban-search`      | Patterns for banned domains     | `10.10.34.35 blocked`    |
| `pg-host`         | PostgreSQL hostname             | `localhost`              |
| `pg-user`         | PostgreSQL username             | `postgres`               |
| `pg-password`     | PostgreSQL password             | `secret`                 |
| `pg-db`           | PostgreSQL database name        | `blacklist_db`           |

### Optional Parameters

| Parameter              | Default    | Description                                         |
|------------------------|------------|-----------------------------------------------------|
| `dns-timeout`          | `5`        | DNS query timeout in seconds (1-300)                |
| `pg-port`              | `5432`     | PostgreSQL port                                     |
| `pg-schema`            | `public`   | Database schema                                     |
| `pg-ssl`               | `false`    | Enable SSL/TLS                                      |
| `pg-ssl-mode`          | `require`  | SSL mode (disable, require, verify-ca, verify-full) |
| `pg-ssl-root-cert`     | -          | Path to SSL certificate                             |
| `additional-tags`      | -          | Custom tags (key=value format)                      |
| `ban-tag`              | `BAN`      | Tag value for banned domains                        |
| `sanction-tag`         | `SANCTION` | Tag value for sanctioned domains                    |
| `sanction-buffer-size` | `10`       | Sanctioned domains buffer size                      |
| `ban-buffer-size`      | `10`       | Banned domains buffer size                          |
| `log-level`            | `info`     | Logging level (debug, info, warn, error)            |

## 📖 Documentation

**For comprehensive documentation, see [DOCUMENTATION.md](./DOCUMENTATION.md)**

The full documentation includes:
- Detailed architecture and workflow
- Installation instructions
- Advanced configuration examples
- Security considerations
- Performance tuning guide
- Troubleshooting guide
- Complete bug fix changelog

## 🛡️ Security

### Recent Security Fixes (v2.0)

- ✅ **SQL Injection**: Fixed schema name interpolation vulnerability
- ✅ **Race Conditions**: Atomic check-and-add operations
- ✅ **Resource Exhaustion**: Goroutine semaphore limiting (max 1000)
- ✅ **Input Validation**: Comprehensive validation for all configuration parameters
- ✅ **Nil Pointer Safety**: Proper null checks for DNS responses

### Best Practices

1. **Use SSL in Production**:
   ```corefile
   pg-ssl true
   pg-ssl-mode verify-full
   pg-ssl-root-cert /path/to/ca-cert.pem
   ```

2. **Protect Your Corefile**:
   ```bash
   chmod 600 /etc/coredns/Corefile
   ```

3. **Use Environment Variables for Secrets**:
   ```corefile
   pg-password $POSTGRES_PASSWORD
   ```

## 🎯 How It Works

1. **DNS Query Interception**: Plugin intercepts DNS queries passing through CoreDNS
2. **Upstream Analysis**: Queries configured upstream DNS servers in background goroutines
3. **Pattern Matching**: Searches responses for ban/sanction patterns
4. **Buffering**: Adds matching domains to in-memory buffers
5. **Database Flush**: Writes buffered domains to PostgreSQL when buffer limit reached

```
DNS Query → CoreDNS → Blacklist Watcher → Upstream DNS Servers
                              ↓
                      Pattern Detection
                              ↓
                      In-Memory Buffer
                              ↓
                    PostgreSQL Database
```

## 🔍 Example Use Cases

### 1. Network Censorship Monitoring
Track which domains are being blocked or censored by monitoring DNS responses for specific patterns.

### 2. Threat Intelligence
Build a database of malicious domains by detecting domains that resolve to known bad IP addresses.

### 3. Compliance Monitoring
Monitor and record access to restricted content for compliance and audit purposes.

### 4. Geo-Location Analysis
Tag domains with geographic metadata to analyze regional censorship patterns.

## 📊 Performance

- **Concurrent Query Limit**: 1000 (configurable via code)
- **Buffer Sizes**: 1-100,000 domains (configurable)
- **Database Writes**: Batched for efficiency
- **Thread-Safe**: Mutex-protected critical sections
- **Non-Blocking**: DNS queries run in background goroutines

## 📝 License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/MrMohebi/coredns_blacklist_watcher/issues)
- **Documentation**: [DOCUMENTATION.md](./DOCUMENTATION.md)

---

**Made with ❤️ for the CoreDNS community**
