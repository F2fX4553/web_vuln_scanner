#!/usr/bin/env python3
"""
Open Redirect Vulnerability Scanner Module
"""

from urllib.parse import urlparse, parse_qs, urlencode
import requests

class OpenRedirectScanner:
    def __init__(self, scanner):
        self.scanner = scanner
        self.payloads = self._load_payloads()
        
    def _load_payloads(self):
        """Load open redirect payloads from file or use default ones"""
        try:
            with open('payloads/redirect_payloads.txt', 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            # Default open redirect payloads if file not found
            return [
                "https://example.com", 
                "//example.com", 
                "https:example.com", 
                "https://evil.com",
                "//evil.com",
                "https://google.com",
                "//google.com",
                "data:text/html,<script>alert(1)</script>",
                "javascript:alert(1)",
                "https://attacker.com/",
                "/\\example.com",
                "https:/\/\example.com",
                "/%0D/example.com",
                "/%2F/example.com",
                "/%5C/example.com",
                "/%09/example.com",
                "/%0a/example.com"
            ]
    
    def check_open_redirect(self, url):
        """Check for open redirect vulnerabilities with multiple payloads"""
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        try:
            query_params = parse_qs(parsed.query)
        except ValueError:
            return
        
        # Common parameter names that might be used for redirects
        redirect_params = [
            'redirect', 'url', 'next', 'redir', 'return', 'returnto', 
            'goto', 'link', 'target', 'dest', 'destination', 'continue',
            'redirect_uri', 'redirect_url', 'callback', 'back', 'return_path',
            'returnUrl', 'redirectUrl', 'redirect_to', 'path', 'to'
        ]
        
        # Test each parameter that might be used for redirects
        for param_name in query_params:
            if any(redir in param_name.lower() for redir in redirect_params):
                # Test a subset of payloads to avoid too many requests
                test_payloads = self.payloads[:5] if len(self.payloads) > 5 else self.payloads
                
                for payload in test_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    
                    query_string = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                    
                    try:
                        response = self.scanner.session.get(test_url, timeout=self.scanner.timeout, allow_redirects=False)
                        
                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get('Location', '')
                            
                            # Check if the redirect goes to an external domain
                            if 'example.com' in location or 'evil.com' in location or 'google.com' in location or 'attacker.com' in location:
                                # Track successful payload
                                if url not in self.scanner.successful_payloads:
                                    self.scanner.successful_payloads[url] = {}
                                if "OpenRedirect" not in self.scanner.successful_payloads[url]:
                                    self.scanner.successful_payloads[url]["OpenRedirect"] = []
                                
                                self.scanner.successful_payloads[url]["OpenRedirect"].append({
                                    'parameter': param_name,
                                    'payload': payload,
                                    'redirected_to': location
                                })
                                
                                self.scanner.report_vulnerability(
                                    url, 
                                    "Open Redirect", 
                                    f"Parameter: {param_name}, Redirects to: {location}, Payload: {payload}",
                                    "MEDIUM",
                                    {
                                        'parameter': param_name,
                                        'payload': payload,
                                        'redirected_to': location
                                    }
                                )
                                return
                    
                    except requests.exceptions.RequestException:
                        continue