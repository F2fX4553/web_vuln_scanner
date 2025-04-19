#!/usr/bin/env python3
"""
JavaScript Analyzer for Web Vulnerability Scanner
"""

import re
from urllib.parse import urljoin

class JavaScriptAnalyzer:
    def __init__(self, scanner):
        """Initialize the JavaScript Analyzer"""
        self.scanner = scanner
        self.logger = scanner.logger
    
    def extract_urls_from_js(self, base_url, js_content):
        """Extract URLs from JavaScript content"""
        if not js_content:
            return
        
        # Look for URLs in various formats
        # 1. Look for strings that look like URLs
        url_patterns = [
            r'https?://[^\s\'"]+',  # http:// or https:// URLs
            r'//[^\s\'"]+',  # Protocol-relative URLs
            r'/[a-zA-Z0-9_\-./]+',  # Absolute paths
            r'[\'"][a-zA-Z0-9_\-./]+\.(?:html|php|asp|jsp|json|xml|js|css)[\'"]'  # Relative paths with extensions
        ]
        
        discovered_urls = set()
        
        for pattern in url_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # Clean up the URL
                url = match.strip('\'"')
                
                # Convert to absolute URL if needed
                if url.startswith('//'):
                    url = 'https:' + url
                elif not url.startswith(('http://', 'https://')):
                    url = urljoin(base_url, url)
                
                # Add to discovered URLs
                if url.startswith(('http://', 'https://')):
                    discovered_urls.add(url)
        
        # Look for API endpoints
        api_patterns = [
            r'api/[^\s\'"]+',
            r'v[0-9]+/[^\s\'"]+',
            r'rest/[^\s\'"]+',
            r'graphql[^\s\'"]*'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                url = match.strip('\'"')
                url = urljoin(base_url, url)
                if url.startswith(('http://', 'https://')):
                    discovered_urls.add(url)
                    # Also add to API endpoints for specific API scanning
                    self.scanner.api_endpoints.add(url)
        
        # Add discovered URLs to scan list if they're not already visited
        for url in discovered_urls:
            if url not in self.scanner.visited_urls and len(self.scanner.urls_to_scan) < self.scanner.max_urls:
                self.scanner.urls_to_scan.add(url)
                self.logger.debug(f"Found URL in JavaScript: {url}")