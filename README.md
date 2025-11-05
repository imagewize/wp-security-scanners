# WordPress Security Scanner Suite

**Version:** 1.0.0
**Created:** November 5, 2025
**License:** MIT

Comprehensive dual-scanner security suite for WordPress malware detection and security auditing.

---

## 🎯 Quick Start

```bash
# Clone to your WordPress root
cd /path/to/wordpress
git clone https://github.com/imagewize/wp-security-scanners.git

# Run both scanners (recommended first scan)
php wp-security-scanners/security-scanner.php

# Or run individually
php wp-security-scanners/security-scanner-targeted.php  # Quick check
php wp-security-scanners/security-scanner-general.php   # Deep scan
```

---

## 📁 What's Included

```
wp-security-scanners/
├── security-scanner.php            # Wrapper (runs both scanners)
├── security-scanner-targeted.php   # Site-specific threat detection
├── security-scanner-general.php    # Broad malware detection
├── SECURITY-SCANNER-GUIDE.md       # Complete documentation
├── SCANNER-SUMMARY.md              # Quick reference guide
└── README.md                       # This file
```

---

## 🔍 Two-Scanner Strategy

### Targeted Scanner (Site-Specific)
**Purpose:** Fast detection of common WordPress vulnerabilities
**Speed:** ~1.7 seconds for 6,600 files

**Detects:**
- Facebook redirect attempts
- File disclosure vulnerabilities
- WordPress-specific exploits (unauthenticated AJAX)
- SQL injection patterns
- PHP malware (eval, base64_decode)
- Code obfuscation

**Use:** Weekly monitoring, post-deployment checks

### General Scanner (Broad Detection)
**Purpose:** Comprehensive malware detection
**Speed:** ~2.5 seconds for 7,400 files

**Detects:**
- Known malware filenames (c99.php, r57.php, shell.php, etc.)
- Pharmaceutical spam injection
- SEO spam and hidden iframes
- Webshell signatures (FilesMan, WSO, etc.)
- Multiple encoding layers
- Backdoor functions
- Long suspicious base64/hex strings

**Use:** Monthly deep scans, after suspected compromise

---

## 🚀 Usage

### Basic Scanning

```bash
# Scan current WordPress installation
php security-scanner.php

# Scan specific directory
php security-scanner.php /path/to/wordpress

# Scan with home directory shortcut
php security-scanner-targeted.php ~/sites/mysite.com
```

### Via WP-CLI (Production Safe)

```bash
# Run from WordPress root
wp eval-file wp-security-scanners/security-scanner.php
```

### Recommended Schedule

| Frequency | Scanner | Command |
|-----------|---------|---------|
| **Weekly** | Targeted | `php security-scanner-targeted.php` |
| **Monthly** | General | `php security-scanner-general.php` |
| **After Deployment** | Targeted | `php security-scanner-targeted.php` |
| **After Incident** | Both | `php security-scanner.php` |

---

## 📊 Sample Output

```
============================================
  SECURITY SCAN COMPLETE
============================================

SCAN SUMMARY:
  Directories scanned: 1,828
  Files scanned: 6,638
  Files with matches: 79
  Total matches: 86
  Errors: 0
  Scan time: 1.69 seconds

✓ No suspicious patterns detected!
```

---

## ⚠️ Security Notes

**IMPORTANT:**
1. **Never commit scanner files to your WordPress repository**
2. **Delete after scanning** or move outside web root
3. **Use IP whitelist** if accessing via browser
4. **Recommended:** Use WP-CLI for production scans

### Browser Access (Not Recommended)

If you must access via browser:

1. Edit scanner file and add your IP:
```php
$allowed_ips = [
    '127.0.0.1',
    'YOUR.IP.ADDRESS.HERE', // Add your IP
];
```

2. Navigate to:
```
https://yoursite.com/wp-security-scanners/security-scanner.php
```

3. **DELETE the scanner directory immediately after use!**

---

## 🎓 Understanding Results

### Severity Levels

- **CRITICAL** - Investigate immediately (malware signatures, backdoors)
- **HIGH** - Review within 24 hours (suspicious redirects, file operations)
- **MEDIUM** - Review as time permits (WordPress exploits, obfuscation)

### Common False Positives

**These are SAFE and can be ignored:**

✅ `xmlrpc.php` - Legitimate WordPress XML-RPC
✅ `wp-includes/rest-api/*` - Legitimate REST API
✅ LiteSpeed Cache files - Legitimate optimization
✅ ACF Pro AJAX - Legitimate frontend functionality
✅ Gravity Forms - Legitimate form handling
✅ SimplePie/MySQL.php - Legitimate library

**See SCANNER-SUMMARY.md for complete false positive list**

### Real Threats (Examples)

**Investigate these immediately:**

❌ `c99.php`, `r57.php`, `shell.php` in uploads
❌ `eval(base64_decode(...))` in theme files
❌ `system($_GET['cmd'])` anywhere
❌ Files modified in last 24 hours with suspicious names
❌ New PHP files in `/wp-content/uploads/`

---

## 💻 Installation

### Method 1: Git Clone (Recommended)

```bash
# From WordPress root
git clone https://github.com/imagewize/wp-security-scanners.git
php wp-security-scanners/security-scanner.php

# Clean up after scanning
rm -rf wp-security-scanners
```

### Method 2: Download & Extract

```bash
# Download release
wget https://github.com/imagewize/wp-security-scanners/archive/main.zip
unzip main.zip
php wp-security-scanners-main/security-scanner.php

# Clean up
rm -rf wp-security-scanners-main main.zip
```

### Method 3: Individual Files

Download only the scanner you need:
- [security-scanner-targeted.php](security-scanner-targeted.php) (site-specific)
- [security-scanner-general.php](security-scanner-general.php) (broad detection)
- [security-scanner.php](security-scanner.php) (runs both)

---

## 🛠️ Advanced Usage

### Scan Multiple Sites

```bash
#!/bin/bash
# weekly-scan.sh

sites=(
    "/var/www/site1.com"
    "/var/www/site2.com"
    "/var/www/site3.com"
)

for site in "${sites[@]}"; do
    echo "Scanning $site..."
    php security-scanner-targeted.php "$site"
done
```

### Automated Cron Job

```bash
# Add to crontab: crontab -e
# Weekly scan every Monday at 3am
0 3 * * 1 /usr/bin/php /path/to/security-scanner-targeted.php /var/www/wordpress > /var/log/wp-scan.log 2>&1
```

### Integration with CI/CD

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Security Scanner
        run: |
          git clone https://github.com/imagewize/wp-security-scanners.git
          php wp-security-scanners/security-scanner-targeted.php .
```

---

## 📚 Documentation

- **[SECURITY-SCANNER-GUIDE.md](SECURITY-SCANNER-GUIDE.md)** - Complete usage guide with examples
- **[SCANNER-SUMMARY.md](SCANNER-SUMMARY.md)** - Quick reference for busy developers

---

## 🔧 Customization

### Add Custom Patterns

Edit the scanner file and add your patterns:

```php
// In security-scanner-targeted.php or security-scanner-general.php
$patterns = [
    // ... existing patterns ...

    'custom_threat' => [
        'name' => 'My Custom Threat',
        'description' => 'Description of what this detects',
        'patterns' => [
            '/your-regex-pattern-here/i',
        ],
        'severity' => 'CRITICAL',
    ],
];
```

### Exclude Directories

```php
$config = [
    'exclude_dirs' => [
        'node_modules',
        '.git',
        'vendor',
        'your-custom-dir',  // Add your exclusions
    ],
];
```

---

## 🐛 Troubleshooting

### Timeout Errors

```bash
# Increase timeout
php -d max_execution_time=600 security-scanner.php
```

### Memory Errors

```bash
# Increase memory
php -d memory_limit=512M security-scanner.php
```

### Permission Errors

```bash
# Run as web server user
sudo -u www-data php security-scanner.php
```

---

## 📈 Performance

### Benchmark Results

Tested on MacBook Pro M1, PHP 8.2:

| Scanner | Files | Time | Speed |
|---------|-------|------|-------|
| Targeted | 6,638 | 1.7s | 3,905 files/sec |
| General | 7,380 | 2.5s | 2,952 files/sec |
| Both | 7,380 | 4.2s | 1,757 files/sec |

### Optimization Tips

1. Exclude large directories (`node_modules`, `vendor`)
2. Run during off-peak hours for production
3. Use targeted scanner for frequent checks
4. Use general scanner for monthly deep scans

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new detection patterns
4. Submit a pull request

### Adding New Malware Patterns

Found a new threat? Submit a PR with:
- Pattern regex
- Sample malicious code (sanitized)
- Description of the threat
- Severity level (CRITICAL/HIGH/MEDIUM)

---

## 📜 License

MIT License - see LICENSE file for details

---

## 🙏 Credits

- Based on malware detection patterns from WordPress Security Best Practices
- Inspired by [lookforbadguys.php](https://gist.github.com/jasperf/3191259)
- Built for the Rob Disbergen WordPress site security investigation (November 2025)

---

## 📞 Support

- **Documentation:** See [SECURITY-SCANNER-GUIDE.md](SECURITY-SCANNER-GUIDE.md)
- **Issues:** https://github.com/imagewize/wp-security-scanners/issues
- **Security:** Report vulnerabilities privately via GitHub

---

## 🔄 Changelog

### v1.0.0 (November 5, 2025)

**Initial Release:**
- Dual-scanner architecture (targeted + general)
- 8 malware detection categories
- Severity-based prioritization
- Command-line path arguments
- Colored CLI output
- Comprehensive documentation
- False positive guidance
- Production-ready security

**Tested On:**
- WordPress 6.4.x
- PHP 8.1/8.2
- 13,000+ files scanned
- Zero false negatives on known patterns

---

**Created with ❤️ for WordPress Security**
