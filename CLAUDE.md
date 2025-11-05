# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a **WordPress security scanner suite** for malware detection and security auditing. It consists of three standalone PHP scripts that scan WordPress installations for malicious code, backdoors, and security vulnerabilities. The scripts are designed to be run on WordPress sites, not in a development environment with dependencies.

**Important Context:** These are security analysis tools, not malware. They detect and report on malicious patterns but do not execute or propagate malicious code. The repository contains regex patterns and detection logic for identifying common WordPress exploits.

## Architecture

### Dual-Scanner Strategy

The suite uses two complementary scanners for comprehensive coverage:

1. **Targeted Scanner** (`security-scanner-targeted.php`)
   - Site-specific threat detection based on the November 2025 Rob Disbergen WordPress investigation
   - Focuses on: Facebook redirects, file disclosure, WordPress-specific exploits, SQL injection, PHP malware (eval/base64), obfuscation
   - Fast execution (~1.7s for 6,600 files)
   - Pattern-based detection using regex matching

2. **General Scanner** (`security-scanner-general.php`)
   - Broad-spectrum malware detection for unknown threats
   - Focuses on: Known malware filenames, pharma hacks, webshells (c99/r57/WSO), SEO spam, backdoors
   - Comprehensive scan (~2.5s for 7,400 files)
   - Filename matching + pattern detection

3. **Wrapper Script** (`security-scanner.php`)
   - Simple orchestrator that runs both scanners sequentially
   - Uses `passthru()` to execute child scanner processes
   - Provides unified output with color-coded results

### Core Design Patterns

**Self-Contained Scripts:** Each scanner is a single-file PHP script with no external dependencies. This allows them to be dropped into any WordPress installation and run immediately.

**Pattern-Based Detection:** All scanners use a `$patterns` array where each pattern has:
- `name`: Human-readable threat name
- `description`: What the pattern detects
- `patterns`: Array of regex patterns
- `severity`: CRITICAL/HIGH/MEDIUM

**Recursive Directory Scanning:** Both scanners use `RecursiveDirectoryIterator` to traverse the WordPress file structure, with configurable exclusions (node_modules, .git, vendor, cache directories).

**Security-First Access Control:** Scripts include IP whitelist protection when accessed via web browser, and recommend WP-CLI for production use.

## Running the Scanners

### Development/Testing

```bash
# Run both scanners on current directory
php security-scanner.php

# Run individual scanners
php security-scanner-targeted.php
php security-scanner-general.php

# Scan specific WordPress installation
php security-scanner.php /path/to/wordpress
php security-scanner-targeted.php ~/sites/mysite.com

# Increase limits for large installations
php -d max_execution_time=600 -d memory_limit=512M security-scanner.php
```

### Production Usage

```bash
# Recommended: Use WP-CLI from WordPress root
wp eval-file wp-security-scanners/security-scanner.php

# Run as web server user if permission issues
sudo -u www-data php security-scanner.php
```

### Testing Changes

After modifying detection patterns:

1. Test on a known-clean WordPress installation (should report no threats)
2. Test pattern matching by creating test files with sanitized malware signatures
3. Verify performance hasn't degraded (check scan time in output)
4. Test false positive handling (legitimate plugins like ACF Pro, Gravity Forms should not trigger alerts)

## Key Configuration

Both scanners share similar configuration in the `$config` array:

```php
$config = [
    'start_path' => dirname(__FILE__, 4),  // WordPress root (3 levels up from theme)
    'exclude_dirs' => ['node_modules', '.git', 'vendor', 'wp-content/uploads/cache'],
    'file_extensions' => ['php', 'js', 'txt', 'htm', 'html'],
    'max_execution_time' => 300,
    'max_file_size' => 5 * 1024 * 1024,  // Skip files >5MB
];
```

**Path Detection:** The scanners auto-detect WordPress root by going up 4 levels from the script location (assumes placement in `wp-content/themes/[theme]/`), but accept command-line path arguments for flexibility.

**IP Whitelist (Web Access):** Located at top of each scanner file, defaults to localhost only. Modify `$allowed_ips` array if browser access is required (not recommended for production).

## Adding New Detection Patterns

### For Site-Specific Threats (Targeted Scanner)

Edit `security-scanner-targeted.php` and add to the `$patterns` array:

```php
'your_pattern_key' => [
    'name' => 'Descriptive Threat Name',
    'description' => 'What this pattern detects and why it matters',
    'patterns' => [
        '/your-regex-pattern/i',
        '/alternative-pattern/i',
    ],
    'severity' => 'CRITICAL',  // or HIGH, MEDIUM
],
```

### For General Malware (General Scanner)

Edit `security-scanner-general.php`:

**For filename-based detection:**
```php
$malware_filenames = [
    'c99.php', 'shell.php', 'your-malware-file.php',
];
```

**For content pattern detection:**
```php
$patterns = [
    'your_category' => [
        'name' => 'Category Name',
        'patterns' => ['/pattern/i'],
        'severity' => 'CRITICAL',
    ],
];
```

### Pattern Writing Guidelines

- Use case-insensitive matching (`/i` flag) for broader detection
- Escape regex special characters: `\.`, `\(`, `\[`, etc.
- Test patterns against legitimate code to avoid false positives
- Be specific enough to avoid matching common WordPress core functions
- Document any known false positives in the pattern description

## File Structure

```
wp-security-scanners/
├── security-scanner.php              # Wrapper (runs both scanners)
├── security-scanner-targeted.php     # Site-specific threat detection
├── security-scanner-general.php      # Broad malware detection
├── README.md                         # User-facing documentation
├── SECURITY-SCANNER-GUIDE.md        # Detailed usage guide
├── SCANNER-SUMMARY.md               # Quick reference
└── CLAUDE.md                        # This file
```

## Important Development Notes

### Working with Security Code

- **These scripts analyze malware but are not malware themselves**
- You can read, analyze, document, and answer questions about the detection logic
- When adding patterns, use sanitized/defanged examples in comments
- Never add code that would execute malicious actions

### False Positives

The following are known safe patterns that may trigger alerts:

- `xmlrpc.php` - Legitimate WordPress XML-RPC (disable if not used)
- `wp-includes/rest-api/*` - Legitimate REST API endpoints
- LiteSpeed Cache plugin files
- Advanced Custom Fields (ACF) Pro AJAX handlers
- Gravity Forms frontend form handling
- SimplePie library MySQL.php file

When adding new patterns, test against these plugins to avoid false positives.

### Performance Considerations

- Both scanners process 6,000-7,400 files in 1.7-2.5 seconds on modern hardware
- `max_file_size` config skips large files (default 5MB) to prevent memory issues
- Exclusion list prevents scanning unnecessary directories (node_modules, vendor)
- Regex patterns are optimized for speed (no backtracking, specific anchors)

### Security Best Practices

1. **Never commit scanner files to a WordPress repository** - they should be temporary tools
2. **Delete after scanning** or move outside web root
3. **Use WP-CLI for production** - avoid browser access
4. **IP whitelist if browser access required** - modify `$allowed_ips` array
5. **Test in staging first** - especially when adding new patterns

## Documentation

- **[README.md](README.md)** - Quick start guide, installation, basic usage
- **[SECURITY-SCANNER-GUIDE.md](SECURITY-SCANNER-GUIDE.md)** - Comprehensive usage guide with examples
- **[SCANNER-SUMMARY.md](SCANNER-SUMMARY.md)** - Quick reference for developers

## Version History

**v1.0.0 (November 5, 2025)** - Initial release
- Dual-scanner architecture
- 8 malware detection categories
- Tested on WordPress 6.4.x with PHP 8.1/8.2
- 13,000+ files scanned in development
