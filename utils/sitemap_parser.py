#!/usr/bin/env python3
"""
Sitemap Parser for Web Vulnerability Scanner
"""

import requests
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

class SitemapParser:
    def __init__(self, scanner):
        """Initialize the Sitemap Parser"""
        self.scanner = scanner
        self.logger = scanner.logger
        self.session = scanner.session
        self.timeout = scanner.timeout
    
    def parse_sitemap(self, sitemap_url):
        """Parse a sitemap XML file and extract URLs"""
        try:
            self.logger.debug(f"Parsing sitemap: {sitemap_url}")
            response = self.session.get(sitemap_url, timeout=self.timeout)
            
            if response.status_code != 200:
                self.logger.debug(f"Failed to fetch sitemap: {sitemap_url}, status code: {response.status_code}")
                return
            
            # Check if it's a sitemap index
            if '<sitemapindex' in response.text:
                self.parse_sitemap_index(sitemap_url, response.text)
            else:
                self.parse_sitemap_urls(sitemap_url, response.text)
        
        except Exception as e:
            self.logger.debug(f"Error parsing sitemap {sitemap_url}: {e}")
    
    def parse_sitemap_index(self, base_url, content):
        """Parse a sitemap index file and process each sitemap"""
        try:
            # Register the XML namespaces
            namespaces = {
                'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'
            }
            
            # Parse the XML
            root = ET.fromstring(content)
            
            # Extract sitemap URLs
            for sitemap in root.findall('.//sm:sitemap/sm:loc', namespaces):
                sitemap_url = sitemap.text
                if sitemap_url:
                    self.parse_sitemap(sitemap_url)
        
        except Exception as e:
            self.logger.debug(f"Error parsing sitemap index: {e}")
    
    def parse_sitemap_urls(self, base_url, content):
        """Parse a sitemap file and extract URLs"""
        try:
            # Register the XML namespaces
            namespaces = {
                'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'
            }
            
            # Parse the XML
            root = ET.fromstring(content)
            
            # Extract URLs
            for url_element in root.findall('.//sm:url/sm:loc', namespaces):
                url = url_element.text
                if url and url not in self.scanner.visited_urls:
                    # Check if we should add external domains
                    if not self.scanner.external_domains:
                        parsed_base = urlparse(base_url)
                        parsed_url = urlparse(url)
                        if parsed_base.netloc != parsed_url.netloc:
                            continue
                    
                    # Add to scan list if we haven't reached the limit
                    if len(self.scanner.urls_to_scan) < self.scanner.max_urls:
                        self.scanner.urls_to_scan.add(url)
                        self.logger.debug(f"Added URL from sitemap: {url}")
        
        except Exception as e:
            self.logger.debug(f"Error parsing sitemap URLs: {e}")