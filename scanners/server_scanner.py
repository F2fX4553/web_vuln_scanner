#!/usr/bin/env python3
"""
Server Misconfiguration Scanner module for the Web Vulnerability Scanner
"""

import re
import requests
from urllib.parse import urlparse, urljoin

class ServerScanner:
    def __init__(self, scanner):
        """Initialize the Server Misconfiguration scanner"""
        self.scanner = scanner
        self.sensitive_files = [
            '/.git/HEAD', '/.git/config', '/.svn/entries', '/.env',
            '/wp-config.php', '/config.php', '/configuration.php',
            '/database.yml', '/settings.py', '/config.js', '/config.json',
            '/backup', '/backup.zip', '/backup.tar.gz', '/backup.sql',
            '/phpinfo.php', '/info.php', '/test.php', '/server-status',
            '/server-info', '/.htaccess', '/web.config', '/robots.txt',
            '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/.well-known/security.txt', '/error_log', '/debug.log',
            '/console', '/admin', '/administrator', '/phpmyadmin',
            '/adminer.php', '/elmah.axd', '/trace.axd'
        ]
    
    def check_server_misconfigurations(self, url):
        """Check for server misconfigurations"""
        self.scanner.logger.info(f"Checking for server misconfigurations on {url}")
        
        # Check for sensitive file exposure
        self._check_sensitive_files(url)
        
        # Check for directory listing
        self._check_directory_listing(url)
        
        # Check for server information disclosure
        self._check_server_info_disclosure(url)
        
        # Check for default credentials
        self._check_default_credentials(url)
        
        # Check for dangerous HTTP methods
        self._check_dangerous_http_methods(url)
    
    def _check_sensitive_files(self, url):
        """Check for sensitive file exposure"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for file_path in self.sensitive_files:
            file_url = urljoin(base_url, file_path)
            try:
                response = self.scanner.session.get(
                    file_url,
                    timeout=self.scanner.timeout,
                    allow_redirects=False  # Don't follow redirects for this check
                )
                
                # Check if the file exists (status code 200)
                if response.status_code == 200:
                    # Check if the response contains actual content (not just a generic error page)
                    if len(response.text) > 0 and '404' not in response.text.lower() and 'not found' not in response.text.lower():
                        severity = "HIGH" if file_path in ['/.git/config', '/.env', '/wp-config.php', '/config.php'] else "MEDIUM"
                        
                        self.scanner.report_vulnerability(
                            url,
                            "Sensitive File Exposure",
                            f"Sensitive file {file_path} is accessible",
                            severity,
                            {
                                "file_url": file_url,
                                "file_path": file_path,
                                "content_length": len(response.text)
                            }
                        )
            
            except requests.exceptions.RequestException as e:
                self.scanner.logger.error(f"Error checking sensitive file {file_url}: {e}")
    
    def _check_directory_listing(self, url):
        """Check for directory listing"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Common directories to check
        directories = [
            '/images', '/uploads', '/assets', '/static', '/media',
            '/backup', '/files', '/data', '/logs', '/temp', '/tmp'
        ]
        
        for directory in directories:
            dir_url = urljoin(base_url, directory)
            try:
                response = self.scanner.session.get(
                    dir_url,
                    timeout=self.scanner.timeout,
                    allow_redirects=True
                )
                
                # Check for directory listing indicators
                if response.status_code == 200 and (
                    'Index of' in response.text or
                    'Directory Listing' in response.text or
                    '<title>Index of' in response.text
                ):
                    self.scanner.report_vulnerability(
                        url,
                        "Directory Listing Enabled",
                        f"Directory listing is enabled for {directory}",
                        "MEDIUM",
                        {
                            "directory_url": dir_url
                        }
                    )
            
            except requests.exceptions.RequestException as e:
                self.scanner.logger.error(f"Error checking directory listing for {dir_url}: {e}")
    
    def _check_server_info_disclosure(self, url):
        """Check for server information disclosure"""
        try:
            response = self.scanner.session.get(
                url,
                timeout=self.scanner.timeout,
                allow_redirects=True
            )
            
            # Check for server header
            server_header = response.headers.get('Server')
            if server_header:
                self.scanner.report_vulnerability(
                    url,
                    "Server Information Disclosure",
                    f"Server header reveals: {server_header}",
                    "LOW",
                    {
                        "type": "Header Disclosure",
                        "header": "Server",
                        "value": server_header
                    }
                )
            
            # Check for X-Powered-By header
            powered_by = response.headers.get('X-Powered-By')
            if powered_by:
                self.scanner.report_vulnerability(
                    url,
                    "Technology Information Disclosure",
                    f"X-Powered-By header reveals: {powered_by}",
                    "LOW",
                    {
                        "type": "Header Disclosure",
                        "header": "X-Powered-By",
                        "value": powered_by
                    }
                )
            
            # Check for other informative headers
            informative_headers = [
                'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator',
                'X-Drupal-Cache', 'X-Drupal-Dynamic-Cache', 'X-Varnish',
                'X-Magento-Cache-Debug', 'X-Wix-Request-Id', 'X-Shopify-Stage'
            ]
            
            for header in informative_headers:
                value = response.headers.get(header)
                if value:
                    self.scanner.report_vulnerability(
                        url,
                        "Technology Information Disclosure",
                        f"{header} header reveals: {value}",
                        "LOW",
                        {
                            "type": "Header Disclosure",
                            "header": header,
                            "value": value
                        }
                    )
        
        except requests.exceptions.RequestException as e:
            self.scanner.logger.error(f"Error checking server info disclosure on {url}: {e}")
    
    def _check_default_credentials(self, url):
        """Check for default credentials on common admin panels"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Common admin panels and their default credentials
        admin_panels = [
            {
                'path': '/admin',
                'credentials': [('admin', 'admin'), ('admin', 'password'), ('admin', '123456')]
            },
            {
                'path': '/wp-admin',
                'credentials': [('admin', 'admin'), ('admin', 'password'), ('wordpress', 'wordpress')]
            },
            {
                'path': '/administrator',
                'credentials': [('admin', 'admin'), ('admin', 'password'), ('administrator', 'administrator')]
            },
            {
                'path': '/phpmyadmin',
                'credentials': [('root', ''), ('root', 'root'), ('root', 'password')]
            }
        ]
        
        for panel in admin_panels:
            panel_url = urljoin(base_url, panel['path'])
            try:
                # First check if the panel exists
                response = self.scanner.session.get(
                    panel_url,
                    timeout=self.scanner.timeout,
                    allow_redirects=True
                )
                
                # If the panel exists (status code 200 or 401/403 for protected panels)
                if response.status_code in [200, 401, 403]:
                    # Look for login form
                    if '<form' in response.text.lower() and ('login' in response.text.lower() or 'password' in response.text.lower()):
                        self.scanner.report_vulnerability(
                            url,
                            "Admin Panel Detected",
                            f"Admin panel detected at {panel['path']}",
                            "LOW",
                            {
                                "admin_url": panel_url
                            }
                        )
                        
                        # Note: We're not actually testing default credentials here to avoid ethical issues
                        # Just reporting the admin panel existence
            
            except requests.exceptions.RequestException as e:
                self.scanner.logger.error(f"Error checking admin panel at {panel_url}: {e}")
    
    def _check_dangerous_http_methods(self, url):
        """Check for dangerous HTTP methods"""
        try:
            # Send OPTIONS request to check allowed methods
            response = self.scanner.session.options(
                url,
                timeout=self.scanner.timeout
            )
            
            # Check Allow header
            allowed_methods = response.headers.get('Allow', '')
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            
            found_dangerous = [method for method in dangerous_methods if method in allowed_methods]
            
            if found_dangerous:
                self.scanner.report_vulnerability(
                    url,
                    "Dangerous HTTP Methods Enabled",
                    f"Potentially dangerous HTTP methods are enabled: {', '.join(found_dangerous)}",
                    "MEDIUM",
                    {
                        "allowed_methods": allowed_methods,
                        "dangerous_methods": found_dangerous
                    }
                )
            
            # Specifically check for TRACE method (potential XST vulnerability)
            if 'TRACE' in allowed_methods:
                try:
                    trace_response = self.scanner.session.request(
                        'TRACE',
                        url,
                        timeout=self.scanner.timeout,
                        headers={'X-Custom-Header': 'XST-Test'}
                    )
                    
                    # If the response contains our custom header, TRACE is working
                    if 'X-Custom-Header: XST-Test' in trace_response.text:
                        self.scanner.report_vulnerability(
                            url,
                            "Cross-Site Tracing (XST) Vulnerability",
                            "TRACE method is enabled and reflects request headers, which could lead to XST attacks",
                            "MEDIUM",
                            {
                                "trace_response": trace_response.text[:200] + "..." if len(trace_response.text) > 200 else trace_response.text
                            }
                        )
                except:
                    pass
        
        except requests.exceptions.RequestException as e:
            self.scanner.logger.error(f"Error checking HTTP methods on {url}: {e}")