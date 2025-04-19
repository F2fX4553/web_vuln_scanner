# Web Vulnerability Scanner

A comprehensive, modular web application security scanner designed to identify common vulnerabilities in web applications.

## Overview

The Web Vulnerability Scanner is a Python-based tool that automates the process of identifying security vulnerabilities in web applications. It employs a modular architecture to scan for various types of vulnerabilities, including Cross-Site Scripting (XSS), SQL Injection, API security issues, server misconfigurations, and Content Security Policy problems.

This tool is designed for security professionals, penetration testers, and developers who need to assess the security posture of web applications. By automating the detection of common vulnerabilities, it helps organizations identify and remediate security issues before they can be exploited by malicious actors.

## Features

- **Multiple Vulnerability Detection**:
  - Cross-Site Scripting (XSS) detection: Identifies reflected, stored, and DOM-based XSS vulnerabilities
  - SQL Injection scanning: Detects error-based, time-based, and boolean-based SQL injection vulnerabilities
  - API security assessment: Discovers API endpoints and checks for common API security issues
  - Server misconfiguration identification: Finds sensitive file exposure, directory listing, and information disclosure
  - Content Security Policy analysis: Evaluates CSP headers for security weaknesses
  - CORS misconfiguration detection: Identifies insecure cross-origin resource sharing settings

- **Flexible Scanning Options**:
  - Target specific URLs or scan from a list
  - Configurable crawling depth with intelligent URL discovery
  - Rate limiting to prevent overwhelming target servers
  - Multi-threaded scanning for improved performance
  - Ability to include or exclude external domains during crawling
  - Custom timeout settings for slow-responding servers

- **Comprehensive Reporting**:
  - HTML reports with interactive elements and collapsible sections
  - JSON reports for programmatic analysis and integration with other tools
  - Visual charts for vulnerability distribution and severity breakdown
  - Detailed vulnerability information with severity ratings (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  - Timestamps and scan duration metrics
  - Recommendations for remediation

- **Customizable Settings**:
  - User-agent configuration for mimicking different browsers
  - Cookie management for authenticated scanning
  - Timeout settings for network requests
  - Verbosity control for detailed logging
  - Scan type selection for targeted assessments

## Architecture

The scanner follows a modular design pattern, with specialized components for different vulnerability types:

1. **Core Scanner (`web_vuln_scanner.py`)**: 
   - Coordinates the scanning process
   - Manages URL crawling and discovery
   - Handles multi-threading and rate limiting
   - Integrates all scanner modules
   - Processes command-line arguments
   - Configures logging and reporting

2. **Scanner Modules**:
   - `xss_scanner.py`: Detects Cross-Site Scripting vulnerabilities using pattern matching and payload injection
   - `sql_scanner.py`: Identifies SQL Injection vulnerabilities through error detection and time-based analysis
   - `api_scanner.py`: Assesses API security issues by discovering endpoints and testing for common vulnerabilities
   - `server_scanner.py`: Checks for server misconfigurations including sensitive file exposure and information disclosure
   - `csp_scanner.py`: Analyzes Content Security Policy implementation for security weaknesses

3. **Utility Modules**:
   - `report_generator.py`: Creates detailed HTML and JSON reports with visualization capabilities

## Technical Details

### Vulnerability Detection Methods

#### Cross-Site Scripting (XSS)
- **Reflected XSS**: Injects payloads in URL parameters and form fields, then analyzes responses for unfiltered reflections
- **Stored XSS**: Submits payloads to storage points (forms, comments) and checks if they're rendered in subsequent page loads
- **DOM-based XSS**: Analyzes JavaScript code for unsafe DOM manipulation patterns and tests with specialized payloads

#### SQL Injection
- **Error-based**: Injects SQL syntax that may trigger database errors, then analyzes responses for error messages
- **Time-based**: Uses time-delay SQL commands to detect blind SQL injection vulnerabilities
- **Boolean-based**: Injects conditional SQL statements and analyzes differences in responses

#### API Security
- **Endpoint Discovery**: Uses common API path patterns and response analysis to identify API endpoints
- **Authentication Testing**: Checks if sensitive API endpoints require proper authentication
- **Information Exposure**: Analyzes API responses for sensitive data leakage
- **CORS Testing**: Checks for misconfigured cross-origin resource sharing headers
- **Rate Limiting**: Tests for missing or inadequate rate limiting protections

#### Server Misconfigurations
- **Sensitive File Exposure**: Checks for access to configuration files, backup files, and other sensitive resources
- **Directory Listing**: Tests for enabled directory browsing
- **Information Disclosure**: Analyzes HTTP headers for server information leakage
- **Default Credentials**: Identifies admin panels and checks for default login credentials
- **Dangerous HTTP Methods**: Tests for enabled PUT, DELETE, and other potentially dangerous HTTP methods

#### Content Security Policy
- **Header Analysis**: Checks for presence and configuration of CSP headers
- **Directive Evaluation**: Analyzes CSP directives for unsafe settings like 'unsafe-inline' or 'unsafe-eval'
- **Missing Protections**: Identifies missing critical directives that could lead to security vulnerabilities

### Crawling and URL Discovery

The scanner employs an intelligent crawling system that:
- Parses HTML to extract links from anchor tags
- Handles relative and absolute URLs correctly
- Respects robots.txt directives (optional)
- Maintains a frontier of URLs to visit
- Tracks visited URLs to avoid duplicate scanning
- Implements depth limiting to prevent infinite crawling
- Provides domain filtering to stay within the target scope

### Multi-threading and Performance

To optimize scanning performance, the scanner:
- Uses a thread pool for concurrent URL scanning
- Implements configurable thread count
- Provides rate limiting to prevent overwhelming target servers
- Uses connection pooling for efficient HTTP requests
- Implements timeout handling for unresponsive servers

## Comprehensive Installation and Usage Guide

### System Requirements

- Operating System: Windows, Linux, or macOS
- Python 3.7 or newer
- Internet connection to access target websites
- Storage: At least 100MB of free space
- Memory: At least 2GB RAM (4GB recommended)

### Required Packages

- requests: For HTTP requests
- beautifulsoup4: For HTML parsing
- matplotlib: For chart generation in reports
- concurrent.futures (standard library): For multi-threading

### Installation Steps

#### 1. Download the Tool from GitHub

```bash
git clone https://github.com/yourusername/web-vulnerability-scanner.git
cd web-vulnerability-scanner
```

3. Verify installation:

```bash
python web_vuln_scanner.py --help
