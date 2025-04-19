#!/usr/bin/env python3
"""
Information Disclosure Vulnerability Scanner Module
"""

import re

class InfoDisclosureScanner:
    def __init__(self, scanner):
        self.scanner = scanner
    
    def check_information_disclosure(self, url, response):
        """Check for information disclosure vulnerabilities"""
        # Check for sensitive information in HTML comments
        comment_pattern = re.compile(r'<!--(.+?)-->', re.DOTALL)
        comments = comment_pattern.findall(response.text)
        
        sensitive_patterns = [
            # Credentials and secrets
            re.compile(r'password|passwd|pwd|secret|key|token|api[_\-]?key', re.I),
            # Development info
            re.compile(r'todo|fixme|hack|note to self|debug|remove this', re.I),
            # Server info
            re.compile(r'server path|absolute path|root directory', re.I),
            # Database info
            re.compile(r'database|db_|sql|mysqli|pdo', re.I),
            # IP addresses
            re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            # Email addresses
            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        ]
        
        for comment in comments:
            for pattern in sensitive_patterns:
                matches = pattern.findall(comment)
                if matches:
                    # Clean up the comment for display
                    clean_comment = comment.strip()
                    if len(clean_comment) > 100:
                        clean_comment = clean_comment[:97] + "..."
                    
                    self.scanner.report_vulnerability(
                        url,
                        "Information Disclosure in HTML Comment",
                        f"Potentially sensitive information found: {', '.join(matches)}. Comment: '{clean_comment}'",
                        "MEDIUM",
                        {
                            'type': 'HTML Comment',
                            'sensitive_info': matches,
                            'comment': clean_comment
                        }
                    )
                    break  # Only report once per comment
        
        # Check for version information disclosure
        version_patterns = [
            # Common frameworks and libraries
            (r'jquery[.-](\d+\.\d+\.\d+)', "jQuery"),
            (r'bootstrap[.-](\d+\.\d+\.\d+)', "Bootstrap"),
            (r'angular[.-](\d+\.\d+\.\d+)', "Angular"),
            (r'react[.-](\d+\.\d+\.\d+)', "React"),
            (r'vue[.-](\d+\.\d+\.\d+)', "Vue.js"),
            (r'wordpress[.-](\d+\.\d+\.\d+)', "WordPress"),
            (r'php[.-](\d+\.\d+\.\d+)', "PHP"),
            (r'apache[.-](\d+\.\d+\.\d+)', "Apache"),
            (r'nginx[.-](\d+\.\d+\.\d+)', "Nginx")
        ]
        
        for pattern, name in version_patterns:
            matches = re.findall(pattern, response.text, re.I)
            if matches:
                self.scanner.report_vulnerability(
                    url,
                    "Version Information Disclosure",
                    f"Detected {name} version {matches[0]} which may be outdated and contain vulnerabilities",
                    "LOW",
                    {
                        'type': 'Version Disclosure',
                        'software': name,
                        'version': matches[0]
                    }
                )
        
        # Check for server information in headers
        server_header = response.headers.get('Server', '')
        if server_header and not server_header.lower() == 'server':
            self.scanner.report_vulnerability(
                url,
                "Server Information Disclosure",
                f"Server header reveals: {server_header}",
                "LOW",
                {
                    'type': 'Header Disclosure',
                    'header': 'Server',
                    'value': server_header
                }
            )
        
        # Check for other technology revealing headers
        tech_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-Runtime', 'X-Version']
        for header in tech_headers:
            if header in response.headers:
                self.scanner.report_vulnerability(
                    url,
                    "Technology Information Disclosure",
                    f"Header '{header}' reveals: {response.headers[header]}",
                    "LOW",
                    {
                        'type': 'Header Disclosure',
                        'header': header,
                        'value': response.headers[header]
                    }
                )