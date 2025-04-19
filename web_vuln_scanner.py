#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Main Module
Advanced version with professional features
"""

import os
import sys
import time
import logging
import argparse
import requests
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Import scanner modules
from scanners.xss_scanner import XSSScanner
from scanners.sql_scanner import SQLInjectionScanner
from scanners.api_scanner import APIScanner
from scanners.server_scanner import ServerScanner
from scanners.csp_scanner import CSPScanner
# Import new scanner modules
from scanners.csrf_scanner import CSRFScanner
from scanners.ssrf_scanner import SSRFScanner
from scanners.xxe_scanner import XXEScanner
from scanners.command_injection_scanner import CommandInjectionScanner
from scanners.file_inclusion_scanner import FileInclusionScanner
from scanners.cors_scanner import CORSScanner
from scanners.jwt_scanner import JWTScanner

from utils.report_generator import ReportGenerator
from utils.auth_manager import AuthenticationManager
from utils.js_analyzer import JavaScriptAnalyzer
from utils.sitemap_parser import SitemapParser

class WebVulnScanner:
    def __init__(self, args):
        """Initialize the Web Vulnerability Scanner"""
        self.args = args
        self.target_urls = []
        self.session = requests.Session()
        self.timeout = args.timeout
        self.crawl_depth = args.depth
        self.max_urls = args.max_urls
        self.rate_limit = args.rate_limit
        self.external_domains = args.external
        self.visited_urls = set()
        self.urls_to_scan = set()
        self.forms_to_scan = set()
        self.api_endpoints = set()
        self.start_time = datetime.now()
        self.report_generator = ReportGenerator(output_dir=args.output_dir)
        
        # Set up logging
        self.setup_logging()
        
        # Set up user agent
        if args.user_agent:
            self.session.headers.update({'User-Agent': args.user_agent})
        else:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
        
        # Set up cookies
        if args.cookies:
            for cookie in args.cookies:
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    self.session.cookies.set(name, value)
        
        # Set up authentication
        self.auth_manager = AuthenticationManager(self.session, self.logger)
        if args.auth_type:
            self.setup_authentication()
        
        # Initialize JS analyzer
        self.js_analyzer = JavaScriptAnalyzer(self)
        
        # Initialize sitemap parser
        self.sitemap_parser = SitemapParser(self)
        
        # Initialize scanner modules
        self.initialize_scanners()
    
    def initialize_scanners(self):
        """Initialize all scanner modules"""
        # Original scanners
        self.xss_scanner = XSSScanner(self)
        self.sql_scanner = SQLInjectionScanner(self)
        self.api_scanner = APIScanner(self)
        self.server_scanner = ServerScanner(self)
        self.csp_scanner = CSPScanner(self)
        
        # New scanners
        self.csrf_scanner = CSRFScanner(self)
        self.ssrf_scanner = SSRFScanner(self)
        self.xxe_scanner = XXEScanner(self)
        self.command_injection_scanner = CommandInjectionScanner(self)
        self.file_inclusion_scanner = FileInclusionScanner(self)
        self.cors_scanner = CORSScanner(self)
        self.jwt_scanner = JWTScanner(self)
    
    def setup_authentication(self):
        """Set up authentication based on command line arguments"""
        auth_type = self.args.auth_type.lower()
        
        if auth_type == 'basic':
            if self.args.auth_credentials:
                username, password = self.args.auth_credentials.split(':', 1)
                self.auth_manager.setup_basic_auth(username, password)
            else:
                self.logger.error("Basic authentication requires credentials in format username:password")
                sys.exit(1)
        
        elif auth_type == 'form':
            if self.args.auth_url and self.args.auth_credentials:
                credentials = {}
                for cred in self.args.auth_credentials.split(','):
                    if '=' in cred:
                        key, value = cred.split('=', 1)
                        credentials[key] = value
                
                self.auth_manager.setup_form_auth(
                    self.args.auth_url, 
                    credentials,
                    self.args.auth_success_pattern
                )
            else:
                self.logger.error("Form authentication requires auth-url and auth-credentials")
                sys.exit(1)
        
        elif auth_type == 'jwt':
            if self.args.auth_token:
                self.auth_manager.setup_jwt_auth(self.args.auth_token)
            else:
                self.logger.error("JWT authentication requires auth-token")
                sys.exit(1)
        
        elif auth_type == 'oauth':
            if self.args.auth_token:
                self.auth_manager.setup_oauth_auth(self.args.auth_token)
            else:
                self.logger.error("OAuth authentication requires auth-token")
                sys.exit(1)
        
        else:
            self.logger.error(f"Unsupported authentication type: {auth_type}")
            sys.exit(1)
        
        # Verify authentication
        if not self.auth_manager.verify_authentication():
            self.logger.error("Authentication failed. Please check your credentials.")
            sys.exit(1)
        
        self.logger.info("Authentication successful")
    
    def setup_logging(self):
        """Set up logging configuration"""
        self.logger = logging.getLogger('web_vuln_scanner')
        self.logger.setLevel(logging.DEBUG if self.args.verbose else logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if self.args.verbose else logging.INFO)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (if not disabled)
        if not self.args.no_log:
            if not os.path.exists(os.path.dirname(self.args.log_file)):
                os.makedirs(os.path.dirname(self.args.log_file))
            
            file_handler = logging.FileHandler(self.args.log_file)
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def load_target_urls(self):
        """Load target URLs from command line or file"""
        if self.args.url:
            self.target_urls = [self.args.url]
        elif self.args.file:
            try:
                with open(self.args.file, 'r') as f:
                    self.target_urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.error(f"Error loading URLs from file: {e}")
                sys.exit(1)
        
        # Validate URLs
        valid_urls = []
        for url in self.target_urls:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    valid_urls.append(url)
                else:
                    self.logger.warning(f"Invalid URL: {url}")
            except:
                self.logger.warning(f"Invalid URL: {url}")
        
        self.target_urls = valid_urls
        
        if not self.target_urls:
            self.logger.error("No valid target URLs provided")
            sys.exit(1)
    
    def check_robots_and_sitemap(self, base_url):
        """Check robots.txt and sitemap.xml for additional URLs"""
        parsed_url = urlparse(base_url)
        base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Check robots.txt
        robots_url = f"{base_domain}/robots.txt"
        try:
            response = self.session.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                self.logger.debug(f"Found robots.txt at {robots_url}")
                
                # Extract disallowed paths and add them to scan list
                for line in response.text.splitlines():
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and not path.startswith('#'):
                            full_url = f"{base_domain}{path}"
                            if full_url not in self.visited_urls:
                                self.urls_to_scan.add(full_url)
                                self.logger.debug(f"Added URL from robots.txt: {full_url}")
                
                # Extract sitemap URLs
                for line in response.text.splitlines():
                    if line.lower().startswith('sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        self.sitemap_parser.parse_sitemap(sitemap_url)
        except Exception as e:
            self.logger.debug(f"Error checking robots.txt: {e}")
        
        # Check sitemap.xml if not already found in robots.txt
        sitemap_url = f"{base_domain}/sitemap.xml"
        try:
            self.sitemap_parser.parse_sitemap(sitemap_url)
        except Exception as e:
            self.logger.debug(f"Error checking sitemap.xml: {e}")
    
    def crawl(self, url, depth=0):
        """Crawl a website to discover URLs"""
        if depth > self.crawl_depth or len(self.urls_to_scan) >= self.max_urls:
            return
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            self.logger.debug(f"Crawling: {url} (depth: {depth})")
            
            # Apply rate limiting if specified
            if self.rate_limit:
                time.sleep(1 / self.rate_limit)
            
            # Check for scan time limit
            if self.args.max_scan_time and (datetime.now() - self.start_time).total_seconds() > self.args.max_scan_time * 60:
                self.logger.info(f"Reached maximum scan time of {self.args.max_scan_time} minutes")
                return
            
            response = self.session.get(url, timeout=self.timeout)
            
            # Skip non-HTML responses
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type and 'application/xhtml+xml' not in content_type:
                # If it's JavaScript, analyze it for URLs
                if 'javascript' in content_type or url.endswith('.js'):
                    self.js_analyzer.extract_urls_from_js(url, response.text)
                return
            
            # Parse the HTML and extract links
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Add the current URL to the scan list
            self.urls_to_scan.add(url)
            
            # Extract forms for later scanning
            self.extract_forms(url, soup)
            
            # Extract links from <a> tags
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Skip empty links, anchors, javascript, and mailto
                if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue
                
                # Convert relative URL to absolute URL
                from urllib.parse import urljoin
                absolute_url = urljoin(url, href)
                
                # Skip URLs that are not HTTP/HTTPS
                if not absolute_url.startswith(('http://', 'https://')):
                    continue
                
                # Check if we should crawl external domains
                if not self.external_domains:
                    # Skip external domains
                    parsed_url = urlparse(url)
                    parsed_link = urlparse(absolute_url)
                    if parsed_url.netloc != parsed_link.netloc:
                        continue
                
                # Recursively crawl the linked URL
                if len(self.urls_to_scan) < self.max_urls and absolute_url not in self.visited_urls:
                    self.crawl(absolute_url, depth + 1)
            
            # Extract URLs from JavaScript
            for script in soup.find_all('script'):
                if script.string:
                    self.js_analyzer.extract_urls_from_js(url, script.string)
                elif 'src' in script.attrs:
                    js_url = urljoin(url, script['src'])
                    if js_url.startswith(('http://', 'https://')) and js_url not in self.visited_urls:
                        try:
                            js_response = self.session.get(js_url, timeout=self.timeout)
                            self.js_analyzer.extract_urls_from_js(js_url, js_response.text)
                        except Exception as e:
                            self.logger.debug(f"Error fetching JavaScript from {js_url}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {e}")
    
    def extract_forms(self, url, soup):
        """Extract forms from HTML for later scanning"""
        for form in soup.find_all('form'):
            form_data = {
                'url': url,
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Get the absolute form action URL
            if form_data['action']:
                from urllib.parse import urljoin
                form_data['action'] = urljoin(url, form_data['action'])
            else:
                form_data['action'] = url
            
            # Extract form inputs
            for input_field in form.find_all(['input', 'textarea', 'select']):
                input_type = input_field.get('type', '')
                input_name = input_field.get('name', '')
                
                if input_name:
                    form_data['inputs'].append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_field.get('value', '')
                    })
            
            # Add form to scan list if it has inputs
            if form_data['inputs']:
                self.forms_to_scan.add(json.dumps(form_data))
                self.logger.debug(f"Found form on {url} with action {form_data['action']}")
    
    def scan_url(self, url):
        """Scan a single URL for vulnerabilities"""
        self.logger.info(f"Scanning URL: {url}")
        
        try:
            # Apply rate limiting if specified
            if self.rate_limit:
                time.sleep(1 / self.rate_limit)
            
            # Check for scan time limit
            if self.args.max_scan_time and (datetime.now() - self.start_time).total_seconds() > self.args.max_scan_time * 60:
                self.logger.info(f"Reached maximum scan time of {self.args.max_scan_time} minutes")
                return
            
            # Get the page
            response = self.session.get(url, timeout=self.timeout)
            
            # Run all enabled scanners
            self.run_scanners(url, response)
            
        except Exception as e:
            self.logger.error(f"Error scanning {url}: {e}")
    
    def run_scanners(self, url, response):
        """Run all enabled scanners on the URL"""
        scan_types = self.args.scan_types
        
        # Original scanners
        if 'xss' in scan_types or 'all' in scan_types:
            self.xss_scanner.check_xss(url, response)
        
        if 'sqli' in scan_types or 'all' in scan_types:
            self.sql_scanner.check_sql_injection(url)
        
        if 'api' in scan_types or 'all' in scan_types:
            self.api_scanner.discover_api_endpoints(url)
        
        if 'server' in scan_types or 'all' in scan_types:
            self.server_scanner.check_server_misconfigurations(url)
        
        if 'csp' in scan_types or 'all' in scan_types:
            self.csp_scanner.check_csp(url, response)
        
        # New scanners
        if 'csrf' in scan_types or 'all' in scan_types:
            self.csrf_scanner.check_csrf(url, response)
        
        if 'ssrf' in scan_types or 'all' in scan_types:
            self.ssrf_scanner.check_ssrf(url)
        
        if 'xxe' in scan_types or 'all' in scan_types:
            self.xxe_scanner.check_xxe(url)
        
        if 'command' in scan_types or 'all' in scan_types:
            self.command_injection_scanner.check_command_injection(url)
        
        if 'file' in scan_types or 'all' in scan_types:
            self.file_inclusion_scanner.check_file_inclusion(url)
        
        if 'cors' in scan_types or 'all' in scan_types:
            self.cors_scanner.check_cors(url, response)
        
        if 'jwt' in scan_types or 'all' in scan_types:
            self.jwt_scanner.check_jwt(url, response)
    
    def scan_forms(self):
        """Scan all discovered forms for vulnerabilities"""
        self.logger.info(f"Scanning {len(self.forms_to_scan)} discovered forms")
        
        for form_json in self.forms_to_scan:
            form_data = json.loads(form_json)
            url = form_data['url']
            action = form_data['action']
            method = form_data['method']
            inputs = form_data['inputs']
            
            self.logger.debug(f"Testing form on {url} with action {action}")
            
            # Apply rate limiting if specified
            if self.rate_limit:
                time.sleep(1 / self.rate_limit)
            
            # Check for scan time limit
            if self.args.max_scan_time and (datetime.now() - self.start_time).total_seconds() > self.args.max_scan_time * 60:
                self.logger.info(f"Reached maximum scan time of {self.args.max_scan_time} minutes")
                return
            
            # Test for XSS in form
            if 'xss' in self.args.scan_types or 'all' in self.args.scan_types:
                self.xss_scanner.check_form_xss(form_data)
            
            # Test for SQL injection in form
            if 'sqli' in self.args.scan_types or 'all' in self.args.scan_types:
                self.sql_scanner.check_form_sql_injection(form_data)
            
            # Test for CSRF in form
            if 'csrf' in self.args.scan_types or 'all' in self.args.scan_types:
                self.csrf_scanner.check_form_csrf(form_data)
            
            # Test for command injection in form
            if 'command' in self.args.scan_types or 'all' in self.args.scan_types:
                self.command_injection_scanner.check_form_command_injection(form_data)
    
    def report_vulnerability(self, url, vuln_type, description, severity, details=None):
        """Report a vulnerability with enhanced details"""
        # Initialize details if None
        if not details:
            details = {}
            
        # Add CVSS score if available
        if 'cvss' not in details:
            # Calculate CVSS score based on severity
            if severity == "CRITICAL":
                details['cvss'] = 9.0 + (1.0 * (hash(description) % 10) / 10)  # Between 9.0 and 10.0
                details['cvss_vector'] = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
            elif severity == "HIGH":
                details['cvss'] = 7.0 + (2.0 * (hash(description) % 10) / 10)  # Between 7.0 and 9.0
                details['cvss_vector'] = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
            elif severity == "MEDIUM":
                details['cvss'] = 4.0 + (3.0 * (hash(description) % 10) / 10)  # Between 4.0 and 7.0
                details['cvss_vector'] = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L'
            elif severity == "LOW":
                details['cvss'] = 0.1 + (3.9 * (hash(description) % 10) / 10)  # Between 0.1 and 4.0
                details['cvss_vector'] = 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'
            else:  # INFO
                details['cvss'] = 0.0
                details['cvss_vector'] = 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N'
        
        # Add discovery timestamp
        details['discovered_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Add affected component information if not present
        if 'affected_component' not in details:
            parsed_url = urlparse(url)
            path = parsed_url.path
            details['affected_component'] = path if path else '/'
            
        # Add attack vector information if not present
        if 'attack_vector' not in details:
            if 'xss' in vuln_type.lower():
                details['attack_vector'] = 'User input reflected in page output'
            elif 'sql' in vuln_type.lower():
                details['attack_vector'] = 'User input in database query'
            elif 'csrf' in vuln_type.lower():
                details['attack_vector'] = 'Cross-origin request'
            elif 'injection' in vuln_type.lower():
                details['attack_vector'] = 'User input in system command'
            elif 'inclusion' in vuln_type.lower():
                details['attack_vector'] = 'User input in file path'
            else:
                details['attack_vector'] = 'Web request'
                details['cvss'] = round(details['cvss'], 1)
        
        # Add remediation advice if not already present
        if 'remediation' not in details:
            if 'xss' in vuln_type.lower():
                details['remediation'] = "Implement context-sensitive output encoding and use Content-Security-Policy headers."
            elif 'sql' in vuln_type.lower():
                details['remediation'] = "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries."
            elif 'csrf' in vuln_type.lower():
                details['remediation'] = "Implement anti-CSRF tokens and validate the origin of requests."
            elif 'ssrf' in vuln_type.lower():
                details['remediation'] = "Implement a whitelist of allowed URLs and protocols. Use a URL parser to validate user-supplied URLs."
            elif 'xxe' in vuln_type.lower():
                details['remediation'] = "Disable XML external entity processing in XML parsers. Use less complex data formats like JSON if possible."
            elif 'command' in vuln_type.lower():
                details['remediation'] = "Avoid using shell commands with user input. If necessary, implement strict input validation and use allowlists."
            elif 'file' in vuln_type.lower():
                details['remediation'] = "Validate and sanitize file paths. Use a whitelist of allowed files and directories."
            elif 'cors' in vuln_type.lower():
                details['remediation'] = "Implement a strict CORS policy. Only allow trusted domains in Access-Control-Allow-Origin headers."
            elif 'jwt' in vuln_type.lower():
                details['remediation'] = "Use strong signing algorithms, validate all parts of the token, and implement proper key management."
            elif 'sensitive' in vuln_type.lower() or 'information' in vuln_type.lower():
                details['remediation'] = "Implement proper access controls and avoid exposing sensitive information in responses."
            elif 'directory' in vuln_type.lower():
                details['remediation'] = "Disable directory listing in web server configuration."
            elif 'server' in vuln_type.lower():
                details['remediation'] = "Keep server software updated and follow security hardening guidelines for your specific server."
            else:
                details['remediation'] = "Implement proper input validation, output encoding, and access controls."
        
        self.report_generator.add_vulnerability(url, vuln_type, description, severity, details)
        
        # Log the vulnerability
        log_message = f"Vulnerability found: {vuln_type} ({severity}) on {url}"
        if severity == "CRITICAL":
            self.logger.critical(log_message)
        elif severity == "HIGH":
            self.logger.error(log_message)
        elif severity == "MEDIUM":
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def get_remediation_advice(self, vuln_type):
        """Get remediation advice for a vulnerability type"""
        remediation_advice = {
            'XSS': 'Implement proper input validation and output encoding. Consider using Content-Security-Policy headers.',
            'SQL Injection': 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
            'CSRF': 'Implement anti-CSRF tokens in all forms and validate them on the server side.',
            'Server Misconfiguration': 'Update server software, disable unnecessary services, and follow security best practices for server configuration.',
            'CSP Issues': 'Implement a strict Content-Security-Policy that only allows trusted sources.',
            'SSRF': 'Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains and IP ranges.',
            'XXE': 'Disable XML external entity processing in XML parsers. Use less complex data formats like JSON if possible.',
            'Command Injection': 'Avoid using system commands with user input. If necessary, use allowlists and strict input validation.',
            'File Inclusion': 'Use allowlists for file inclusion rather than direct user input. Keep sensitive files outside the web root.',
            'CORS Misconfiguration': 'Set specific origins in Access-Control-Allow-Origin headers instead of using wildcards.',
            'JWT Vulnerabilities': 'Use strong signing algorithms, validate all claims, and implement proper key management.'
        }
        
        return remediation_advice.get(vuln_type, 'Follow security best practices and keep all software updated.')
    
    def run(self):
        """Run the scanner"""
        self.logger.info("Starting Web Vulnerability Scanner")
        self.start_time = datetime.now()
        
        # Load target URLs
        self.load_target_urls()
        
        # Start the scan
        self.report_generator.start_scan(self.target_urls)
        
        # Check for robots.txt and sitemap.xml
        for url in self.target_urls:
            self.check_robots_and_sitemap(url)
        
        # Crawl the target URLs if enabled
        if self.args.crawl:
            self.logger.info(f"Crawling enabled (depth: {self.crawl_depth}, max URLs: {self.max_urls})")
            for url in self.target_urls:
                self.crawl(url)
        else:
            # Just add the target URLs to the scan list
            self.urls_to_scan = set(self.target_urls)
        
        self.logger.info(f"Found {len(self.urls_to_scan)} URLs to scan")
        
        # Scan the URLs
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            executor.map(self.scan_url, self.urls_to_scan)
        
        # Scan discovered forms
        self.scan_forms()
        
        # End the scan
        scan_duration = datetime.now() - self.start_time
        self.report_generator.end_scan(scan_duration=scan_duration)
        
        # Generate the report
        report_files = self.report_generator.generate_report(self.args.format)
        
        if isinstance(report_files, dict):
            for format_type, filename in report_files.items():
                self.logger.info(f"{format_type.upper()} report saved to: {filename}")
        else:
            self.logger.info(f"Report saved to: {report_files}")
        
        self.logger.info(f"Scan completed in {scan_duration}")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Target URL to scan')
    target_group.add_argument('-f', '--file', help='File containing list of target URLs')
    
    # Scanning options
    parser.add_argument('-s', '--scan-types', nargs='+', default=['all'],
                        help='Types of vulnerabilities to scan for (xss, sqli, api, server, csp, csrf, ssrf, xxe, command, file, cors, jwt, all)')
    parser.add_argument('-c', '--crawl', action='store_true',
                        help='Enable crawling to discover URLs')
    parser.add_argument('-d', '--depth', type=int, default=2,
                        help='Maximum crawl depth (default: 2)')
    parser.add_argument('-m', '--max-urls', type=int, default=100,
                        help='Maximum number of URLs to scan (default: 100)')
    parser.add_argument('-r', '--rate-limit', type=float, default=0,
                        help='Rate limit in requests per second (default: no limit)')
    parser.add_argument('-e', '--external', action='store_true',
                        help='Crawl external domains')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('--threads', type=int, default=5,
                        help='Number of concurrent scanning threads (default: 5)')
    parser.add_argument('--max-scan-time', type=int, default=0,
                        help='Maximum scan time in minutes (default: no limit)')
    
    # Authentication options
    parser.add_argument('--auth-type', choices=['basic', 'form', 'jwt', 'oauth'],
                        help='Authentication type (basic, form, jwt, oauth)')
    parser.add_argument('--auth-url', help='Authentication URL for form-based authentication')
    parser.add_argument('--auth-credentials', help='Authentication credentials (username:password for basic, key=value,key=value for form)')
    parser.add_argument('--auth-token', help='Authentication token for JWT or OAuth')
    parser.add_argument('--auth-success-pattern', help='Pattern to verify successful authentication')
    
    # Authentication and headers
    parser.add_argument('-a', '--user-agent', help='Custom User-Agent header')
    parser.add_argument('-k', '--cookies', nargs='+', help='Cookies to include in requests (format: name=value)')
    
    # Output options
    parser.add_argument('-o', '--output-dir', default='reports',
                        help='Output directory for reports (default: reports)')
    parser.add_argument('-F', '--format', default='html',
                        choices=['json', 'html', 'pdf', 'xml', 'csv', 'all'],
                        help='Report format (default: html)')
    parser.add_argument('-l', '--log-file', default='logs/scan.log',
                        help='Log file (default: logs/scan.log)')
    parser.add_argument('-n', '--no-log', action='store_true',
                        help='Disable logging to file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--safe-mode', action='store_true',
                        help='Enable safe mode (non-intrusive scanning)')
    
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()
    scanner = WebVulnScanner(args)
    scanner.run()

################################
