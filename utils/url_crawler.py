#!/usr/bin/env python3
"""
URL crawler for the Web Vulnerability Scanner
"""

import re
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

class URLCrawler:
    def __init__(self, max_depth=2, max_urls=100, same_domain_only=True):
        """Initialize the URL crawler"""
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.same_domain_only = same_domain_only
        self.visited_urls = set()
        self.urls_to_visit = []
        self.base_domain = ""
    
    def extract_urls(self, url, html_content):
        """Extract URLs from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        parsed_base_url = urlparse(url)
        self.base_domain = parsed_base_url.netloc
        
        urls = []
        
        # Extract URLs from anchor tags
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            
            # Skip empty links, javascript, and mailto links
            if not href or href.startswith(('javascript:', 'mailto:', 'tel:')):
                continue
            
            # Convert relative URLs to absolute URLs
            absolute_url = urljoin(url, href)
            
            # Parse the URL to check domain
            parsed_url = urlparse(absolute_url)
            
            # Skip URLs with fragments or queries if we've already visited the base URL
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Skip URLs that are not on the same domain if same_domain_only is True
            if self.same_domain_only and parsed_url.netloc != self.base_domain:
                continue
            
            # Skip URLs that are not http or https
            if not parsed_url.scheme in ['http', 'https']:
                continue
            
            # Add the URL to the list if we haven't visited it yet
            if base_url not in self.visited_urls:
                urls.append(absolute_url)
        
        # Extract URLs from form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            
            # Skip empty actions
            if not action:
                continue
            
            # Convert relative URLs to absolute URLs
            absolute_url = urljoin(url, action)
            
            # Parse the URL to check domain
            parsed_url = urlparse(absolute_url)
            
            # Skip URLs that are not on the same domain if same_domain_only is True
            if self.same_domain_only and parsed_url.netloc != self.base_domain:
                continue
            
            # Skip URLs that are not http or https
            if not parsed_url.scheme in ['http', 'https']:
                continue
            
            # Add the URL to the list if we haven't visited it yet
            if absolute_url not in self.visited_urls:
                urls.append(absolute_url)
        
        return urls
    
    def crawl(self, start_url, session=None, logger=None):
        """Crawl a website starting from the given URL"""
        if not session:
            session = requests.Session()
        
        self.urls_to_visit = [(start_url, 0)]  # (url, depth)
        self.visited_urls = set()
        
        while self.urls_to_visit and len(self.visited_urls) < self.max_urls:
            url, depth = self.urls_to_visit.pop(0)
            
            # Skip if we've already visited this URL
            if url in self.visited_urls:
                continue
            
            # Add the URL to the visited set
            self.visited_urls.add(url)
            
            if logger:
                logger.debug(f"Crawling URL: {url} (Depth: {depth})")
            
            try:
                response = session.get(url, timeout=10)
                
                # Skip non-HTML responses
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    continue
                
                # Extract URLs from the response
                if depth < self.max_depth:
                    new_urls = self.extract_urls(url, response.text)
                    
                    # Add new URLs to the queue
                    for new_url in new_urls:
                        if new_url not in self.visited_urls and len(self.visited_urls) < self.max_urls:
                            self.urls_to_visit.append((new_url, depth + 1))
            
            except requests.exceptions.RequestException as e:
                if logger:
                    logger.error(f"Error crawling URL {url}: {e}")
                continue
        
        return list(self.visited_urls)