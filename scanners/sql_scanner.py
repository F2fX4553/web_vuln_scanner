#!/usr/bin/env python3
"""
SQL Injection Scanner module for the Web Vulnerability Scanner
"""

import re
import time
import random
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse

class SQLInjectionScanner:
    def __init__(self, scanner):
        """Initialize the SQL Injection scanner"""
        self.scanner = scanner
        self.payloads = self.load_payloads()
        self.error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\.",
            # PostgreSQL
            r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\.",
            # MS SQL Server
            r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\.",
            # Oracle
            r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
            # IBM DB2
            r"CLI Driver.*DB2", r"DB2 SQL error", r"db2_\w+\(",
            # SQLite
            r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]",
            # Generic
            r"SQL syntax.*", r"Syntax error.*SQL", r"Unclosed quotation mark after the character string",
            r"Incorrect syntax near"
        ]
        
    def load_payloads(self):
        """Load SQL injection payloads from file"""
        payloads = []
        try:
            with open('payloads/sqli_payloads.txt', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except FileNotFoundError:
            # Default payloads if file not found
            payloads = [
                "'", "\"", "1'", "1\"", "1=1", "' OR '1'='1", "\" OR \"1\"=\"1",
                "' OR 1=1 --", "\" OR 1=1 --", "' OR '1'='1' --", "\" OR \"1\"=\"1\" --",
                "admin' --", "admin\" --"
            ]
        
        return payloads
    
    def check_sql_injection(self, url):
        """Check for SQL injection vulnerabilities"""
        self.scanner.logger.info(f"Checking for SQL injection vulnerabilities on {url}")
        
        try:
            # Get the initial response
            response = self.scanner.session.get(url, timeout=self.scanner.timeout)
            
            # Extract forms for testing
            forms = self._extract_forms(url, response.text)
            
            # Test each form
            for form in forms:
                self._test_form(url, form)
            
            # Test URL parameters
            self._test_url_parameters(url)
            
        except requests.exceptions.RequestException as e:
            self.scanner.logger.error(f"Error checking SQL injection on {url}: {e}")
    
    def _extract_forms(self, base_url, html):
        """Extract forms from HTML content"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Convert relative URL to absolute URL
            action_url = urljoin(base_url, action) if action else base_url
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                input_value = input_tag.get('value', '')
                
                # Skip submit buttons and file uploads for SQL injection testing
                if input_type not in ['submit', 'button', 'image', 'reset', 'file']:
                    inputs.append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
            
            forms.append({
                'action': action_url,
                'method': method,
                'inputs': inputs
            })
        
        return forms
    
    def _test_form(self, url, form):
        """Test a form for SQL injection vulnerabilities"""
        self.scanner.logger.debug(f"Testing form on {url} with action {form['action']}")
        
        # For each input in the form
        for input_field in form['inputs']:
            if not input_field['name']:
                continue
                
            # For each payload
            for payload in self.payloads:
                # Prepare the data to submit
                data = {}
                for inp in form['inputs']:
                    if inp['name'] == input_field['name']:
                        data[inp['name']] = payload
                    elif inp['name']:
                        # Use original value or a generic value
                        data[inp['name']] = inp['value'] if inp['value'] else 'test'
                
                try:
                    # Submit the form
                    if form['method'] == 'post':
                        response = self.scanner.session.post(
                            form['action'],
                            data=data,
                            timeout=self.scanner.timeout,
                            allow_redirects=True
                        )
                    else:
                        response = self.scanner.session.get(
                            form['action'],
                            params=data,
                            timeout=self.scanner.timeout,
                            allow_redirects=True
                        )
                    
                    # Check for SQL errors in the response
                    if self._check_sql_errors(response.text):
                        self.scanner.report_vulnerability(
                            url,
                            "SQL Injection Vulnerability",
                            f"SQL error detected via {form['method'].upper()} parameter '{input_field['name']}'",
                            "HIGH",
                            {
                                "form_action": form['action'],
                                "form_method": form['method'],
                                "vulnerable_parameter": input_field['name'],
                                "payload": payload
                            }
                        )
                        return  # Found a vulnerability, no need to test more payloads
                    
                    # Check for time-based SQL injection
                    if 'SLEEP' in payload or 'WAITFOR' in payload or 'pg_sleep' in payload:
                        start_time = time.time()
                        response = self.scanner.session.post(
                            form['action'],
                            data=data,
                            timeout=max(self.scanner.timeout, 10),  # Longer timeout for time-based tests
                            allow_redirects=True
                        ) if form['method'] == 'post' else self.scanner.session.get(
                            form['action'],
                            params=data,
                            timeout=max(self.scanner.timeout, 10),
                            allow_redirects=True
                        )
                        elapsed_time = time.time() - start_time
                        
                        # If response took significantly longer, it might be vulnerable
                        if elapsed_time > 5:  # Assuming the sleep time in payload is 5 seconds
                            self.scanner.report_vulnerability(
                                url,
                                "Time-based SQL Injection",
                                f"Time-based SQL injection detected via {form['method'].upper()} parameter '{input_field['name']}'",
                                "HIGH",
                                {
                                    "form_action": form['action'],
                                    "form_method": form['method'],
                                    "vulnerable_parameter": input_field['name'],
                                    "payload": payload,
                                    "response_time": elapsed_time
                                }
                            )
                            return  # Found a vulnerability, no need to test more payloads
                    
                    # Check for boolean-based SQL injection
                    if ('AND 1=1' in payload or 'AND "a"="a"' in payload or "AND 'a'='a" in payload) and \
                       not ('AND 1=2' in payload or 'AND "a"="b"' in payload or "AND 'a'='b" in payload):
                        # Store the response for the true condition
                        true_response = response.text
                        
                        # Now test with a false condition
                        false_payload = payload.replace('1=1', '1=2').replace('"a"="a"', '"a"="b"').replace("'a'='a", "'a'='b")
                        
                        # Update the data with the false condition
                        data[input_field['name']] = false_payload
                        
                        # Submit the form with the false condition
                        false_response = self.scanner.session.post(
                            form['action'],
                            data=data,
                            timeout=self.scanner.timeout,
                            allow_redirects=True
                        ).text if form['method'] == 'post' else self.scanner.session.get(
                            form['action'],
                            params=data,
                            timeout=self.scanner.timeout,
                            allow_redirects=True
                        ).text
                        
                        # If the responses are significantly different, it might be vulnerable
                        if self._compare_responses(true_response, false_response):
                            self.scanner.report_vulnerability(
                                url,
                                "Boolean-based SQL Injection",
                                f"Boolean-based SQL injection detected via {form['method'].upper()} parameter '{input_field['name']}'",
                                "HIGH",
                                {
                                    "form_action": form['action'],
                                    "form_method": form['method'],
                                    "vulnerable_parameter": input_field['name'],
                                    "payload": payload
                                }
                            )
                            return  # Found a vulnerability, no need to test more payloads
                
                except requests.exceptions.RequestException as e:
                    self.scanner.logger.error(f"Error testing form on {url}: {e}")
    
    def _test_url_parameters(self, url):
        """Test URL parameters for SQL injection vulnerabilities"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            return
        
        self.scanner.logger.debug(f"Testing URL parameters on {url}")
        
        # For each parameter in the URL
        for param_name, param_values in params.items():
            # For each payload
            for payload in self.payloads:
                # Prepare the parameters
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                try:
                    # Build the test URL
                    test_url = url.split('?')[0] + '?' + '&'.join([
                        f"{p}={v[0]}" for p, v in test_params.items()
                    ])
                    
                    # Send the request
                    response = self.scanner.session.get(
                        test_url,
                        timeout=self.scanner.timeout,
                        allow_redirects=True
                    )
                    
                    # Check for SQL errors in the response
                    if self._check_sql_errors(response.text):
                        self.scanner.report_vulnerability(
                            url,
                            "SQL Injection Vulnerability",
                            f"SQL error detected via URL parameter '{param_name}'",
                            "HIGH",
                            {
                                "vulnerable_parameter": param_name,
                                "payload": payload
                            }
                        )
                        return  # Found a vulnerability, no need to test more payloads
                    
                    # Check for time-based SQL injection
                    if 'SLEEP' in payload or 'WAITFOR' in payload or 'pg_sleep' in payload:
                        start_time = time.time()
                        response = self.scanner.session.get(
                            test_url,
                            timeout=max(self.scanner.timeout, 10),  # Longer timeout for time-based tests
                            allow_redirects=True
                        )
                        elapsed_time = time.time() - start_time
                        
                        # If response took significantly longer, it might be vulnerable
                        if elapsed_time > 5:  # Assuming the sleep time in payload is 5 seconds
                            self.scanner.report_vulnerability(
                                url,
                                "Time-based SQL Injection",
                                f"Time-based SQL injection detected via URL parameter '{param_name}'",
                                "HIGH",
                                {
                                    "vulnerable_parameter": param_name,
                                    "payload": payload,
                                    "response_time": elapsed_time
                                }
                            )
                            return  # Found a vulnerability, no need to test more payloads
                    
                    # Check for boolean-based SQL injection
                    if ('AND 1=1' in payload or 'AND "a"="a"' in payload or "AND 'a'='a" in payload) and \
                       not ('AND 1=2' in payload or 'AND "a"="b"' in payload or "AND 'a'='b" in payload):
                        # Store the response for the true condition
                        true_response = response.text
                        
                        # Now test with a false condition
                        false_payload = payload.replace('1=1', '1=2').replace('"a"="a"', '"a"="b"').replace("'a'='a", "'a'='b")
                        
                        # Update the parameters with the false condition
                        test_params[param_name] = [false_payload]
                        
                        # Build the test URL with the false condition
                        false_test_url = url.split('?')[0] + '?' + '&'.join([
                            f"{p}={v[0]}" for p, v in test_params.items()
                        ])
                        
                        # Send the request with the false condition
                        false_response = self.scanner.session.get(
                            false_test_url,
                            timeout=self.scanner.timeout,
                            allow_redirects=True
                        ).text
                        
                        # If the responses are significantly different, it might be vulnerable
                        if self._compare_responses(true_response, false_response):
                            self.scanner.report_vulnerability(
                                url,
                                "Boolean-based SQL Injection",
                                f"Boolean-based SQL injection detected via URL parameter '{param_name}'",
                                "HIGH",
                                {
                                    "vulnerable_parameter": param_name,
                                    "payload": payload
                                }
                            )
                            return  # Found a vulnerability, no need to test more payloads
                
                except requests.exceptions.RequestException as e:
                    self.scanner.logger.error(f"Error testing URL parameter on {url}: {e}")
    
    def _check_sql_errors(self, response_text):
        """Check if the response contains SQL error messages"""
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def _compare_responses(self, response1, response2):
        """
        Compare two responses to determine if they are significantly different
        This is used for boolean-based SQL injection detection
        """
        # Remove dynamic content that might change between requests
        response1 = self._normalize_response(response1)
        response2 = self._normalize_response(response2)
        
        # If the responses are identical, they are not different
        if response1 == response2:
            return False
        
        # Calculate the difference ratio
        import difflib
        diff_ratio = difflib.SequenceMatcher(None, response1, response2).ratio()
        
        # If the responses are less than 95% similar, consider them different
        return diff_ratio < 0.95
    
    def _normalize_response(self, response_text):
        """
        Normalize a response by removing dynamic content
        This helps in comparing responses for boolean-based SQL injection detection
        """
        # Remove timestamps, random tokens, etc.
        normalized = re.sub(r'\d{2}:\d{2}:\d{2}', '', response_text)
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}', '', normalized)
        normalized = re.sub(r'[a-f0-9]{32}', '', normalized)  # MD5 hashes
        normalized = re.sub(r'[a-f0-9]{40}', '', normalized)  # SHA1 hashes
        
        return normalized