#!/usr/bin/env python3
"""
CORS Scanner Module for Web Vulnerability Scanner
"""

from urllib.parse import urlparse

class CORSScanner:
    def __init__(self, scanner):
        """Initialize the CORS Scanner"""
        self.scanner = scanner
        self.logger = scanner.logger
        self.session = scanner.session
        self.timeout = scanner.timeout
    
    def check_cors(self, url, response):
        """Check for CORS misconfigurations"""
        # Get the origin of the URL
        parsed_url = urlparse(url)
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Check for CORS headers in the response
        acao_header = response.headers.get('Access-Control-Allow-Origin')
        acac_header = response.headers.get('Access-Control-Allow-Credentials')
        
        if acao_header:
            # Check for wildcard origin
            if acao_header == '*' and acac_header == 'true':
                self.scanner.report_vulnerability(
                    url=url,
                    vuln_type="CORS Misconfiguration",
                    description="Wildcard Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true",
                    severity="HIGH",
                    details={
                        "acao": acao_header,
                        "acac": acac_header,
                        "remediation": "Do not use wildcard origins with credentials. Specify exact origins instead."
                    }
                )
            
            # Test for origin reflection
            if self.scanner.args.safe_mode:
                # In safe mode, just check if the header looks like it might reflect origins
                if acao_header != '*' and acao_header != origin:
                    self.scanner.report_vulnerability(
                        url=url,
                        vuln_type="CORS Misconfiguration",
                        description="Possible CORS origin reflection detected",
                        severity="MEDIUM",
                        details={
                            "acao": acao_header,
                            "acac": acac_header,
                            "remediation": "Validate and whitelist specific origins instead of reflecting them"
                        }
                    )
            else:
                # In normal mode, test with a malicious origin
                try:
                    evil_origin = "https://evil.example.com"
                    headers = {'Origin': evil_origin}
                    test_response = self.session.get(url, headers=headers, timeout=self.timeout)
                    
                    test_acao = test_response.headers.get('Access-Control-Allow-Origin')
                    test_acac = test_response.headers.get('Access-Control-Allow-Credentials')
                    
                    if test_acao == evil_origin and test_acac == 'true':
                        self.scanner.report_vulnerability(
                            url=url,
                            vuln_type="CORS Misconfiguration",
                            description="Server reflects arbitrary origins in CORS headers with credentials",
                            severity="HIGH",
                            details={
                                "acao": test_acao,
                                "acac": test_acac,
                                "test_origin": evil_origin,
                                "remediation": "Validate and whitelist specific origins instead of reflecting them"
                            }
                        )
                except Exception as e:
                    self.logger.debug(f"Error testing CORS reflection: {e}")