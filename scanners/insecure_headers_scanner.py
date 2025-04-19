#!/usr/bin/env python3
"""
Insecure Headers Vulnerability Scanner Module
"""

class InsecureHeadersScanner:
    def __init__(self, scanner):
        self.scanner = scanner
    
    def check_insecure_headers(self, url, response):
        """Check for missing or insecure security headers"""
        security_headers = {
            'Strict-Transport-Security': {
                'message': 'Missing HSTS header',
                'description': 'HTTP Strict Transport Security (HSTS) header is missing, which helps protect against protocol downgrade attacks and cookie hijacking.'
            },
            'Content-Security-Policy': {
                'message': 'Missing CSP header',
                'description': 'Content Security Policy (CSP) header is missing, which helps mitigate XSS attacks by restricting which resources can be loaded.'
            },
            'X-Content-Type-Options': {
                'message': 'Missing X-Content-Type-Options header',
                'description': 'X-Content-Type-Options header is missing, which prevents browsers from MIME-sniffing a response away from the declared content-type.'
            },
            'X-Frame-Options': {
                'message': 'Missing X-Frame-Options header',
                'description': 'X-Frame-Options header is missing, which helps prevent clickjacking attacks by ensuring the page cannot be embedded in a frame.'
            },
            'X-XSS-Protection': {
                'message': 'Missing X-XSS-Protection header',
                'description': 'X-XSS-Protection header is missing, which enables the cross-site scripting (XSS) filter in browsers.'
            },
            'Referrer-Policy': {
                'message': 'Missing Referrer-Policy header',
                'description': 'Referrer-Policy header is missing, which controls how much referrer information should be included with requests.'
            },
            'Permissions-Policy': {
                'message': 'Missing Permissions-Policy header',
                'description': 'Permissions-Policy header is missing, which allows a site to control which features and APIs can be used in the browser.'
            }
        }
        
        for header, info in security_headers.items():
            if header not in response.headers:
                self.scanner.report_vulnerability(
                    url, 
                    "Insecure Headers", 
                    f"{info['message']}: {info['description']}",
                    "LOW",
                    {
                        'type': 'Missing Security Header',
                        'header': header,
                        'description': info['description']
                    }
                )
        
        # Check for insecure cookie settings
        if 'Set-Cookie' in response.headers:
            cookies = response.headers.getall('Set-Cookie') if hasattr(response.headers, 'getall') else [response.headers['Set-Cookie']]
            
            for cookie in cookies:
                if 'secure' not in cookie.lower():
                    self.scanner.report_vulnerability(
                        url, 
                        "Insecure Cookie", 
                        "Cookie set without 'Secure' flag, which means it can be transmitted over unencrypted HTTP connections",
                        "MEDIUM",
                        {
                            'type': 'Insecure Cookie',
                            'issue': 'Missing Secure flag',
                            'cookie': cookie.split(';')[0]
                        }
                    )
                
                if 'httponly' not in cookie.lower():
                    self.scanner.report_vulnerability(
                        url, 
                        "Insecure Cookie", 
                        "Cookie set without 'HttpOnly' flag, which means it can be accessed by JavaScript",
                        "MEDIUM",
                        {
                            'type': 'Insecure Cookie',
                            'issue': 'Missing HttpOnly flag',
                            'cookie': cookie.split(';')[0]
                        }
                    )
                
                if 'samesite' not in cookie.lower():
                    self.scanner.report_vulnerability(
                        url, 
                        "Insecure Cookie", 
                        "Cookie set without 'SameSite' attribute, which helps prevent CSRF attacks",
                        "LOW",
                        {
                            'type': 'Insecure Cookie',
                            'issue': 'Missing SameSite attribute',
                            'cookie': cookie.split(';')[0]
                        }
                    )