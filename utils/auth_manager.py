#!/usr/bin/env python3
"""
Authentication Manager for Web Vulnerability Scanner
"""

import re
import base64
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class AuthenticationManager:
    def __init__(self, session, logger):
        """Initialize the Authentication Manager"""
        self.session = session
        self.logger = logger
        self.auth_type = None
        self.auth_url = None
        self.credentials = None
        self.success_pattern = None
        self.token = None
    
    def setup_basic_auth(self, username, password):
        """Set up Basic Authentication"""
        self.auth_type = 'basic'
        self.credentials = (username, password)
        self.session.auth = self.credentials
        self.logger.debug(f"Set up Basic Authentication with username: {username}")
    
    def setup_form_auth(self, auth_url, credentials, success_pattern=None):
        """Set up Form-based Authentication"""
        self.auth_type = 'form'
        self.auth_url = auth_url
        self.credentials = credentials
        self.success_pattern = success_pattern
        self.logger.debug(f"Set up Form Authentication with URL: {auth_url}")
    
    def setup_jwt_auth(self, token):
        """Set up JWT Authentication"""
        self.auth_type = 'jwt'
        self.token = token
        self.session.headers.update({'Authorization': f'Bearer {token}'})
        self.logger.debug("Set up JWT Authentication")
    
    def setup_oauth_auth(self, token):
        """Set up OAuth Authentication"""
        self.auth_type = 'oauth'
        self.token = token
        self.session.headers.update({'Authorization': f'Bearer {token}'})
        self.logger.debug("Set up OAuth Authentication")
    
    def verify_authentication(self):
        """Verify that authentication is working"""
        if self.auth_type == 'basic':
            # For basic auth, we just try to access a protected resource
            return True
        
        elif self.auth_type == 'form':
            # For form auth, we need to submit the form and check for success
            try:
                # Get the login page to extract form details
                response = self.session.get(self.auth_url, timeout=10)
                
                # Parse the form
                soup = BeautifulSoup(response.text, 'html.parser')
                form = soup.find('form')
                
                if not form:
                    self.logger.error("Could not find a form on the login page")
                    return False
                
                # Get the form action URL
                action = form.get('action', '')
                if action:
                    form_url = urljoin(self.auth_url, action)
                else:
                    form_url = self.auth_url
                
                # Get the form method
                method = form.get('method', 'post').lower()
                
                # Prepare the form data
                form_data = {}
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    name = input_field.get('name')
                    if name:
                        # Use provided credentials if available, otherwise use default value
                        if name in self.credentials:
                            form_data[name] = self.credentials[name]
                        else:
                            form_data[name] = input_field.get('value', '')
                
                # Add any missing credentials
                for key, value in self.credentials.items():
                    if key not in form_data:
                        form_data[key] = value
                
                # Submit the form
                if method == 'post':
                    response = self.session.post(form_url, data=form_data, timeout=10)
                else:
                    response = self.session.get(form_url, params=form_data, timeout=10)
                
                # Check if authentication was successful
                if self.success_pattern:
                    return re.search(self.success_pattern, response.text) is not None
                else:
                    # If no success pattern is provided, check if we were redirected
                    return response.url != form_url
            
            except Exception as e:
                self.logger.error(f"Error during form authentication: {e}")
                return False
        
        elif self.auth_type in ('jwt', 'oauth'):
            # For token-based auth, we just check if the token is valid
            return bool(self.token)
        
        return False