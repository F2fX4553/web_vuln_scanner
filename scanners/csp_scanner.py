#!/usr/bin/env python3
"""
Content Security Policy Scanner module for the Web Vulnerability Scanner
"""

import re
import requests
from urllib.parse import urlparse

class CSPScanner:
    def __init__(self, scanner):
        """Initialize the CSP scanner"""
        self.scanner = scanner
    
    def check_csp(self, url, response=None):
        """Check for Content Security Policy issues"""
        self.scanner.logger.info(f"Checking Content Security Policy on {url}")
        
        if response is None:
            try:
                response = self.scanner.session.get(
                    url, 
                    timeout=self.scanner.timeout,
                    allow_redirects=True
                )
            except requests.exceptions.RequestException as e:
                self.scanner.logger.error(f"Error checking CSP on {url}: {e}")
                return
        
        # Check if CSP header exists
        csp_header = response.headers.get('Content-Security-Policy')
        csp_report_only = response.headers.get('Content-Security-Policy-Report-Only')
        
        # If no CSP header, report it
        if not csp_header and not csp_report_only:
            self.scanner.report_vulnerability(
                url,
                "Missing Content Security Policy",
                "Content Security Policy header is not set, which could allow various client-side attacks",
                "MEDIUM",
                {
                    "recommendation": "Implement a Content Security Policy header to restrict resource loading"
                }
            )
            return
        
        # Use the actual CSP header or the report-only version
        csp = csp_header or csp_report_only
        
        # Check for unsafe CSP directives
        self._check_unsafe_directives(url, csp)
        
        # Check for missing directives
        self._check_missing_directives(url, csp)
    
    def _check_unsafe_directives(self, url, csp):
        """Check for unsafe CSP directives"""
        # Check for unsafe-inline in script-src or style-src
        if "script-src 'unsafe-inline'" in csp or "style-src 'unsafe-inline'" in csp:
            self.scanner.report_vulnerability(
                url,
                "Unsafe CSP Directive",
                "Content Security Policy contains 'unsafe-inline' directive, which allows inline scripts or styles",
                "MEDIUM",
                {
                    "csp": csp,
                    "unsafe_directive": "unsafe-inline",
                    "recommendation": "Remove 'unsafe-inline' and use nonces or hashes instead"
                }
            )
        
        # Check for unsafe-eval in script-src
        if "script-src 'unsafe-eval'" in csp:
            self.scanner.report_vulnerability(
                url,
                "Unsafe CSP Directive",
                "Content Security Policy contains 'unsafe-eval' directive, which allows the use of eval() and similar functions",
                "MEDIUM",
                {
                    "csp": csp,
                    "unsafe_directive": "unsafe-eval",
                    "recommendation": "Remove 'unsafe-eval' and refactor code to avoid using eval()"
                }
            )
        
        # Check for wildcard (*) in script-src, style-src, or object-src
        if "script-src *" in csp or "style-src *" in csp or "object-src *" in csp:
            self.scanner.report_vulnerability(
                url,
                "Overly Permissive CSP",
                "Content Security Policy contains wildcard (*) for script, style, or object sources",
                "MEDIUM",
                {
                    "csp": csp,
                    "recommendation": "Replace wildcards with specific domains"
                }
            )
    
    def _check_missing_directives(self, url, csp):
        """Check for missing CSP directives"""
        # Important directives to check
        important_directives = [
            'default-src', 'script-src', 'object-src', 'style-src',
            'img-src', 'media-src', 'frame-src', 'font-src',
            'connect-src', 'form-action', 'frame-ancestors'
        ]
        
        missing_directives = []
        
        for directive in important_directives:
            if directive not in csp:
                missing_directives.append(directive)
        
        # If default-src is missing and script-src or object-src is also missing, it's a problem
        if 'default-src' in missing_directives and ('script-src' in missing_directives or 'object-src' in missing_directives):
            self.scanner.report_vulnerability(
                url,
                "Incomplete Content Security Policy",
                "Content Security Policy is missing critical directives",
                "MEDIUM",
                {
                    "csp": csp,
                    "missing_directives": missing_directives,
                    "recommendation": "Add missing directives, especially default-src, script-src, and object-src"
                }
            )
        
        # Check if frame-ancestors is missing (clickjacking protection)
        if 'frame-ancestors' in missing_directives:
            self.scanner.report_vulnerability(
                url,
                "Missing Clickjacking Protection in CSP",
                "Content Security Policy is missing frame-ancestors directive, which helps prevent clickjacking",
                "LOW",
                {
                    "csp": csp,
                    "recommendation": "Add frame-ancestors directive to prevent clickjacking"
                }
            )