# SQL Injection Scanner

A lightweight Python tool for scanning web applications for potential SQL injection vulnerabilities.

## Overview

This tool scans target URLs for possible SQL injection vulnerabilities by sending various payloads to URL parameters and analyzing responses for SQL error patterns. It's designed to help security professionals and developers identify potential security issues in web applications.

## Features

- Tests multiple SQL injection payloads against URL parameters
- Detects common SQL error patterns from various database systems
- Supports custom payload lists
- Detailed logging of scan activities and findings
- Simple command-line interface

## Requirements

- Python 3.6+
- Required packages:
  - requests
  - urllib3

## Installation

1. Clone the repository or download the source code:

```bash
git clone https://github.com/ROHITCRAFTSYT/sql-injection-scanner.git
cd sql-injection-scanner
```

2. Install the required packages:

```bash
pip install requests
```

## Usage

### Basic Usage

Run the script and follow the prompts:

```bash
python sql_injection_scanner.py
```

When prompted, enter the target URL to scan, for example:
```
Enter the target URL to scan (e.g., http://example.com/page?param=value): http://vulnerable-site.com/search?q=test
```

### Custom Payload File

You can create a custom file with SQL injection payloads (one per line) and specify it when creating the scanner:

```python
scanner = SQLInjectionScanner(target_url, payloads_file="my_custom_payloads.txt")
```

## Default Payloads

If no payload file is provided, the scanner uses these default payloads:
- `' OR '1'='1`
- `' OR '1'='1' --`
- `'; DROP TABLE users; --`
- `' UNION SELECT NULL, username, password FROM users --`
- `1; EXEC xp_cmdshell('dir') --`

## Detected Error Patterns

The scanner looks for these error patterns in responses:
- MySQL syntax errors
- MySQL warnings
- Unclosed quotation marks errors
- General SQL syntax errors
- Oracle database errors (ORA-XXXX)
- SQLite errors

## Integrating into Your Own Code

You can import the `SQLInjectionScanner` class and use it in your own Python code:

```python
from sql_injection_scanner import SQLInjectionScanner

target_url = "http://example.com/page?param=value"
scanner = SQLInjectionScanner(target_url)
vulnerabilities_found = scanner.scan()

if vulnerabilities_found:
    print("Vulnerabilities were found!")
else:
    print("No vulnerabilities detected.")
```

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper permission before scanning any website or web application. Unauthorized scanning of systems may be illegal and unethical.

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

Potential improvements:
- Add support for POST requests
- Implement more detection techniques beyond error-based
- Add support for authentication
- Improve payload effectiveness
