#!/usr/bin/env python3
"""
Report Generator Module for Web Vulnerability Scanner
Enhanced with detailed vulnerability reporting and professional risk assessment
"""

import os
import json
import time
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse

class ReportGenerator:
    def __init__(self, scanner=None, output_dir=None):
        """Initialize the Report Generator"""
        self.scanner = scanner
        self.logger = scanner.logger if scanner else None
        self.vulnerabilities = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.target_urls = []
        
        # Handle both initialization methods
        if scanner:
            self.report_file = getattr(scanner.args, 'report_file', 'vulnerability_report.json')
            self.report_format = getattr(scanner.args, 'report_format', 'json')
        else:
            # Default values when initialized with output_dir
            self.output_dir = output_dir or 'reports'
            self.report_file = os.path.join(self.output_dir, f'scan_report_{datetime.now().strftime("%Y%m%d-%H%M%S")}.json')
            self.report_format = 'json'
        
        # Create reports directory if it doesn't exist
        report_dir = os.path.dirname(self.report_file)
        if not report_dir:
            report_dir = 'reports'
            self.report_file = os.path.join(report_dir, os.path.basename(self.report_file))
        
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
            if self.logger:
                self.logger.info(f"Created reports directory: {report_dir}")
    
    def start_scan(self, target_urls=None):
        """Record the start of a scan"""
        self.scan_start_time = datetime.now()
        # Store target_urls if provided
        if target_urls:
            self.target_urls = target_urls
        
        if self.logger:
            self.logger.info(f"Scan started at {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    def end_scan(self, scan_duration=None):
        """Record the end of a scan and generate the report"""
        self.scan_end_time = datetime.now()
        
        if scan_duration is None:
            scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        if self.logger:
            self.logger.info(f"Scan completed at {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            self.logger.info(f"Scan duration: {scan_duration:.2f} seconds")
        
        # Generate the report
        self._generate_report(scan_duration)
    
    def add_vulnerability(self, url=None, vuln_type=None, description=None, severity="LOW", details=None):
        """Add a vulnerability to the report with enhanced details"""
        # Handle both calling conventions:
        # 1. add_vulnerability(vulnerability_dict)
        # 2. add_vulnerability(url, vuln_type, description, severity, details)
        
        if url and isinstance(url, dict):
            # First argument is a vulnerability dictionary
            vulnerability = url
        else:
            # Arguments are individual vulnerability fields
            vulnerability = {
                'url': url,
                'type': vuln_type,
                'description': description,
                'severity': severity,
                'details': details or {}
            }
            
        # Add additional vulnerability metadata
        self._enhance_vulnerability_data(vulnerability)
        
        self.vulnerabilities.append(vulnerability)
        
        # Log the vulnerability if logger exists
        if self.logger:
            severity = vulnerability.get('severity', 'UNKNOWN')
            vuln_type = vulnerability.get('type', 'Unknown')
            url = vulnerability.get('url', 'Unknown URL')
            description = vulnerability.get('description', 'No description')
            cvss = vulnerability.get('cvss_score', 'N/A')
            
            self.logger.warning(f"[{severity}] {vuln_type} - {url} - {description} (CVSS: {cvss})")
    
    def _enhance_vulnerability_data(self, vulnerability):
        """Enhance vulnerability data with additional professional details"""
        # Add timestamp
        vulnerability['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Extract domain from URL
        url = vulnerability.get('url', '')
        if url:
            parsed_url = urlparse(url)
            vulnerability['domain'] = parsed_url.netloc
        
        # Calculate or validate CVSS score
        self._calculate_cvss_score(vulnerability)
        
        # Add CWE information if applicable
        self._add_cwe_information(vulnerability)
        
        # Add remediation guidance
        self._add_remediation_guidance(vulnerability)
        
        # Add exploit information
        self._add_exploit_information(vulnerability)
    
    def _calculate_cvss_score(self, vulnerability):
        """Calculate or validate CVSS score based on severity and vulnerability type"""
        severity = vulnerability.get('severity', 'LOW')
        details = vulnerability.get('details', {})
        vuln_type = vulnerability.get('type', '')
        
        # Use provided CVSS if available
        if details and 'cvss' in details:
            vulnerability['cvss_score'] = details['cvss']
            vulnerability['cvss_vector'] = details.get('cvss_vector', 'N/A')
            return
        
        # Calculate CVSS score based on severity
        base_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.0,
            'MEDIUM': 4.0,
            'LOW': 1.0,
            'INFO': 0.0
        }
        
        # Get base score from severity
        base_score = base_scores.get(severity, 3.0)
        
        # Adjust score based on vulnerability type (add small variation)
        type_adjustment = hash(vuln_type) % 10 / 10.0
        
        # Calculate final score (keep within severity range)
        if severity == 'CRITICAL':
            cvss_score = min(10.0, base_score + type_adjustment)
        elif severity == 'HIGH':
            cvss_score = min(8.9, max(7.0, base_score + type_adjustment))
        elif severity == 'MEDIUM':
            cvss_score = min(6.9, max(4.0, base_score + type_adjustment))
        elif severity == 'LOW':
            cvss_score = min(3.9, max(0.1, base_score + type_adjustment))
        else:  # INFO
            cvss_score = 0.0
        
        vulnerability['cvss_score'] = round(cvss_score, 1)
        
        # Generate a simplified CVSS vector
        if severity == 'CRITICAL':
            vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
        elif severity == 'HIGH':
            vector = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
        elif severity == 'MEDIUM':
            vector = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L'
        elif severity == 'LOW':
            vector = 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'
        else:  # INFO
            vector = 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N'
        
        vulnerability['cvss_vector'] = vector
    
    def _add_cwe_information(self, vulnerability):
        """Add CWE (Common Weakness Enumeration) information based on vulnerability type"""
        vuln_type = vulnerability.get('type', '').lower()
        
        # Map common vulnerability types to CWE IDs
        cwe_mapping = {
            'xss': {'id': 'CWE-79', 'name': 'Cross-site Scripting', 'link': 'https://cwe.mitre.org/data/definitions/79.html'},
            'cross-site scripting': {'id': 'CWE-79', 'name': 'Cross-site Scripting', 'link': 'https://cwe.mitre.org/data/definitions/79.html'},
            'sql': {'id': 'CWE-89', 'name': 'SQL Injection', 'link': 'https://cwe.mitre.org/data/definitions/89.html'},
            'sql injection': {'id': 'CWE-89', 'name': 'SQL Injection', 'link': 'https://cwe.mitre.org/data/definitions/89.html'},
            'csrf': {'id': 'CWE-352', 'name': 'Cross-Site Request Forgery', 'link': 'https://cwe.mitre.org/data/definitions/352.html'},
            'ssrf': {'id': 'CWE-918', 'name': 'Server-Side Request Forgery', 'link': 'https://cwe.mitre.org/data/definitions/918.html'},
            'xxe': {'id': 'CWE-611', 'name': 'XML External Entity Reference', 'link': 'https://cwe.mitre.org/data/definitions/611.html'},
            'command': {'id': 'CWE-77', 'name': 'Command Injection', 'link': 'https://cwe.mitre.org/data/definitions/77.html'},
            'command injection': {'id': 'CWE-77', 'name': 'Command Injection', 'link': 'https://cwe.mitre.org/data/definitions/77.html'},
            'file': {'id': 'CWE-22', 'name': 'Path Traversal', 'link': 'https://cwe.mitre.org/data/definitions/22.html'},
            'file inclusion': {'id': 'CWE-98', 'name': 'File Inclusion', 'link': 'https://cwe.mitre.org/data/definitions/98.html'},
            'cors': {'id': 'CWE-942', 'name': 'Permissive Cross-domain Policy', 'link': 'https://cwe.mitre.org/data/definitions/942.html'},
            'jwt': {'id': 'CWE-347', 'name': 'Improper Verification of Cryptographic Signature', 'link': 'https://cwe.mitre.org/data/definitions/347.html'},
            'sensitive': {'id': 'CWE-200', 'name': 'Information Exposure', 'link': 'https://cwe.mitre.org/data/definitions/200.html'},
            'information disclosure': {'id': 'CWE-200', 'name': 'Information Exposure', 'link': 'https://cwe.mitre.org/data/definitions/200.html'},
            'directory': {'id': 'CWE-548', 'name': 'Directory Listing', 'link': 'https://cwe.mitre.org/data/definitions/548.html'},
            'server': {'id': 'CWE-16', 'name': 'Configuration', 'link': 'https://cwe.mitre.org/data/definitions/16.html'}
        }
        
        # Find matching CWE
        cwe_info = None
        for key, info in cwe_mapping.items():
            if key in vuln_type:
                cwe_info = info
                break
        
        # Default CWE if no match found
        if not cwe_info:
            cwe_info = {'id': 'CWE-693', 'name': 'Protection Mechanism Failure', 'link': 'https://cwe.mitre.org/data/definitions/693.html'}
        
        vulnerability['cwe'] = cwe_info
    
    def _add_remediation_guidance(self, vulnerability):
        """Add remediation guidance based on vulnerability type"""
        vuln_type = vulnerability.get('type', '').lower()
        
        # Default remediation
        remediation = "Implement proper input validation and output encoding."
        
        # Specific remediations based on vulnerability type
        if 'xss' in vuln_type:
            remediation = "Implement context-sensitive output encoding and use Content-Security-Policy headers."
        elif 'sql' in vuln_type:
            remediation = "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries."
        elif 'csrf' in vuln_type:
            remediation = "Implement anti-CSRF tokens and validate the origin of requests."
        elif 'ssrf' in vuln_type:
            remediation = "Implement a whitelist of allowed URLs and protocols. Use a URL parser to validate user-supplied URLs."
        elif 'xxe' in vuln_type:
            remediation = "Disable XML external entity processing in XML parsers. Use less complex data formats like JSON if possible."
        elif 'command' in vuln_type:
            remediation = "Avoid using shell commands with user input. If necessary, implement strict input validation and use allowlists."
        elif 'file' in vuln_type:
            remediation = "Validate and sanitize file paths. Use a whitelist of allowed files and directories."
        elif 'cors' in vuln_type:
            remediation = "Implement a strict CORS policy. Only allow trusted domains in Access-Control-Allow-Origin headers."
        elif 'jwt' in vuln_type:
            remediation = "Use strong signing algorithms, validate all parts of the token, and implement proper key management."
        elif 'sensitive' in vuln_type or 'information' in vuln_type:
            remediation = "Implement proper access controls and avoid exposing sensitive information in responses."
        elif 'directory' in vuln_type:
            remediation = "Disable directory listing in web server configuration."
        elif 'server' in vuln_type:
            remediation = "Keep server software updated and follow security hardening guidelines for your specific server."
        
        vulnerability['remediation'] = remediation
    
    def _add_exploit_information(self, vulnerability):
        """Add information about potential exploit scenarios"""
        vuln_type = vulnerability.get('type', '').lower()
        severity = vulnerability.get('severity', 'LOW')
        
        # Default exploit information
        exploit_info = "This vulnerability could potentially be exploited by malicious actors."
        
        # Specific exploit information based on vulnerability type
        if 'xss' in vuln_type:
            exploit_info = "An attacker could inject malicious scripts that execute in users' browsers, potentially stealing session cookies, redirecting to phishing sites, or performing actions on behalf of the victim."
        elif 'sql' in vuln_type:
            exploit_info = "An attacker could manipulate SQL queries to bypass authentication, access, modify, or delete sensitive data, or execute administrative operations on the database."
        elif 'csrf' in vuln_type:
            exploit_info = "An attacker could trick authenticated users into performing unintended actions on the application without their knowledge or consent."
        elif 'ssrf' in vuln_type:
            exploit_info = "An attacker could force the server to make requests to internal resources or external systems, potentially accessing sensitive data or performing server-side actions."
        elif 'xxe' in vuln_type:
            exploit_info = "An attacker could read local files, perform server-side request forgery, scan internal systems, or execute denial of service attacks."
        elif 'command' in vuln_type:
            exploit_info = "An attacker could execute arbitrary commands on the host operating system, potentially gaining complete control over the server."
        elif 'file' in vuln_type:
            exploit_info = "An attacker could access sensitive files outside the web root directory or include malicious code from remote servers."
        elif 'cors' in vuln_type:
            exploit_info = "An attacker could access sensitive data from a malicious domain by exploiting overly permissive cross-origin resource sharing policies."
        elif 'jwt' in vuln_type:
            exploit_info = "An attacker could forge or tamper with tokens to impersonate users, escalate privileges, or access protected resources."
        elif 'sensitive' in vuln_type or 'information' in vuln_type:
            exploit_info = "An attacker could gather sensitive information about the system, which could be used to plan more targeted attacks."
        elif 'directory' in vuln_type:
            exploit_info = "An attacker could discover sensitive files and gather information about the application structure."
        elif 'server' in vuln_type:
            exploit_info = "An attacker could exploit server misconfigurations to gain unauthorized access or perform denial of service attacks."
        
        # Add impact level based on severity
        impact_levels = {
            'CRITICAL': "This vulnerability has a severe impact and could lead to complete system compromise.",
            'HIGH': "This vulnerability has a significant impact and could lead to sensitive data exposure or partial system compromise.",
            'MEDIUM': "This vulnerability has a moderate impact and could lead to limited data exposure or functionality disruption.",
            'LOW': "This vulnerability has a minor impact with limited consequences.",
            'INFO': "This is an informational finding with minimal direct security impact."
        }
        
        impact = impact_levels.get(severity, "The impact of this vulnerability depends on the specific context.")
        
        vulnerability['exploit_info'] = exploit_info
        vulnerability['impact'] = impact
    
    def _generate_report(self, scan_duration):
        """Generate the vulnerability report"""
        if not self.vulnerabilities:
            if self.logger:
                self.logger.info("No vulnerabilities found")
            return
        
        # Count vulnerabilities by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Log summary if logger exists
        if self.logger:
            self.logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities:")
            for severity, count in severity_counts.items():
                if count > 0:
                    self.logger.info(f"  {severity}: {count}")
        
        # Generate report based on format
        if self.report_format.lower() == 'json':
            self._generate_json_report(scan_duration, severity_counts)
        elif self.report_format.lower() == 'html':
            self._generate_html_report(scan_duration, severity_counts)
        elif self.report_format.lower() == 'csv':
            self._generate_csv_report(scan_duration, severity_counts)
        else:
            self.logger.error(f"Unsupported report format: {self.report_format}")
    
    def _generate_json_report(self, scan_duration, severity_counts):
        """Generate a JSON report"""
        # Initialize scan info with available data
        scan_info = {
            'start_time': self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration_seconds': scan_duration
        }
        
        # Add scanner-specific info if available
        if hasattr(self, 'target_urls'):
            scan_info['target_urls'] = self.target_urls
        elif self.scanner and hasattr(self.scanner, 'target_urls'):
            scan_info['target_urls'] = self.scanner.target_urls
        
        if self.scanner:
            scan_options = {}
            for attr in ['crawl_depth', 'max_urls', 'timeout', 'user_agent']:
                if hasattr(self.scanner, attr):
                    scan_options[attr] = getattr(self.scanner, attr)
            
            if hasattr(self.scanner, 'args') and hasattr(self.scanner.args, 'scanners'):
                scan_options['scanners'] = self.scanner.args.scanners
            
            scan_info['scan_options'] = scan_options
        
        report = {
            'scan_info': scan_info,
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity_counts': severity_counts
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        try:
            with open(self.report_file, 'w') as f:
                json.dump(report, f, indent=4)
            
            if self.logger:
                self.logger.info(f"JSON report saved to {self.report_file}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error saving JSON report: {e}")
    
    def _generate_cwe_html(self, vuln):
        """Generate HTML for CWE information"""
        cwe = vuln.get('cwe', None)
        if not cwe:
            return ""
            
        return f"""
        <div class="cwe-info">
            <h4>CWE Information</h4>
            <p><strong>CWE ID:</strong> {cwe.get('id', 'Unknown')}</p>
            <p><strong>CWE Name:</strong> {cwe.get('name', 'Unknown')}</p>
            <p><strong>Reference:</strong> <a href="{cwe.get('link', '#')}" target="_blank">{cwe.get('link', 'Unknown')}</a></p>
        </div>
        """
    
    def _generate_html_report(self, scan_duration, severity_counts):
        """Generate an enhanced HTML report with detailed vulnerability information"""
        if not self.vulnerabilities:
            if self.logger:
                self.logger.info("No vulnerabilities found - skipping HTML report")
            return

        # Determine HTML report file path
        html_file = self.report_file.replace('.json', '.html')
        
        # Get scan info
        scan_info = {
            'start_time': self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S') if self.scan_start_time else 'Unknown',
            'end_time': self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S') if self.scan_end_time else 'Unknown',
            'duration_seconds': f"{scan_duration:.2f}",
            'target_urls': self.target_urls or getattr(self.scanner, 'target_urls', ['Unknown'])
        }
        
        # Initialize html_content variable
        html_content = ""
        
        # Generate vulnerability cards HTML
        vuln_cards_html = ""
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            severity_class = severity.lower()
            
            # Map severity to color classes
            severity_color_map = {
                'critical': 'critical',
                'high': 'danger',
                'medium': 'warning',
                'low': 'info',
                'info': 'success'
            }
            severity_color = severity_color_map.get(severity_class, 'info')
            
            # Generate vulnerability details
            vuln_cards_html += f"""
            <div class="card mb-3 border-{severity_color}">
              <div class="card-header bg-{severity_color} text-white">
                <h5 class="card-title">{vuln['type']} - {vuln['severity']}</h5>
              </div>
                <div class="vuln-content">
                    <div class="vuln-details">
                        <p><strong>URL:</strong> <a href="{vuln.get('url', '#')}" target="_blank">{vuln.get('url', 'Unknown')}</a></p>
                        <p><strong>Domain:</strong> {vuln.get('domain', 'Unknown')}</p>
                        <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                        <p><strong>Detected:</strong> {vuln.get('timestamp', 'Unknown')}</p>
                    </div>
                    
                    <div class="vuln-risk">
                        <div class="cvss-info">
                            <h4>Risk Assessment</h4>
                            <p><strong>CVSS Score:</strong> <span class="{severity_class}">{vuln.get('cvss_score', 'N/A')}</span></p>
                            <p><strong>CVSS Vector:</strong> <code>{vuln.get('cvss_vector', 'N/A')}</code></p>
                        </div>
                        
                        {self._generate_cwe_html(vuln)}
                        
                        <div class="exploit-info">
                            <h4>Exploit Scenario</h4>
                            <p>{vuln.get('exploit_info', 'No exploit information available')}</p>
                        </div>
                        
                        <div class="impact-info">
                            <h4>Impact</h4>
                            <p>{vuln.get('impact', 'Impact not assessed')}</p>
                        </div>
                    </div>
                    
                    <div class="remediation-info">
                        <h4>Remediation Guidance</h4>
                        <p>{vuln.get('remediation', 'No remediation guidance available')}</p>
                    </div>
                    
                    <div class="details-section">
                        <h4>Technical Details</h4>"""
            
            # Add vulnerability details
            details = vuln.get('details', {})
            details_html = ''
            if isinstance(details, dict):
                for key, value in details.items():
                    details_html += f"""
                        <p><strong>{key}:</strong> {str(value)}</p>"""
            else:
                details_html = f"""
                        <p>{str(details)}</p>"""
            vuln_cards_html += details_html
            
            vuln_cards_html += """
                    </div>
                </div>
            </div>"""
        
        # Generate summary charts data
        severity_data = [
            {'label': 'Critical', 'count': severity_counts.get('CRITICAL', 0), 'color': 'var(--critical-color)'},
            {'label': 'High', 'count': severity_counts.get('HIGH', 0), 'color': 'var(--danger-color)'},
            {'label': 'Medium', 'count': severity_counts.get('MEDIUM', 0), 'color': 'var(--warning-color)'},
            {'label': 'Low', 'count': severity_counts.get('LOW', 0), 'color': 'var(--info-color)'},
            {'label': 'Info', 'count': severity_counts.get('INFO', 0), 'color': 'var(--success-color)'}
        ]
        
        # Generate chart data JSON for JavaScript
        chart_data_json = json.dumps(severity_data)
        
        # Try to use template file if it exists
        template_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates', 'report_template.html')
        
        try:
            if os.path.exists(template_path):
                with open(template_path, 'r') as f:
                    template = f.read()
                
                # Process Jinja2-style template variables
                # First, replace our custom placeholders
                html_content = template
                html_content = html_content.replace('{{REPORT_DATE}}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                html_content = html_content.replace('{{SCAN_START_TIME}}', scan_info['start_time'])
                html_content = html_content.replace('{{SCAN_END_TIME}}', scan_info['end_time'])
                html_content = html_content.replace('{{SCAN_DURATION}}', scan_info['duration_seconds'])
                html_content = html_content.replace('{{TARGET_URLS}}', ', '.join(scan_info['target_urls']))
                html_content = html_content.replace('{{TOTAL_VULNERABILITIES}}', str(len(self.vulnerabilities)))
                html_content = html_content.replace('{{CRITICAL_COUNT}}', str(severity_counts.get('CRITICAL', 0)))
                html_content = html_content.replace('{{HIGH_COUNT}}', str(severity_counts.get('HIGH', 0)))
                html_content = html_content.replace('{{MEDIUM_COUNT}}', str(severity_counts.get('MEDIUM', 0)))
                html_content = html_content.replace('{{LOW_COUNT}}', str(severity_counts.get('LOW', 0)))
                html_content = html_content.replace('{{INFO_COUNT}}', str(severity_counts.get('INFO', 0)))
                html_content = html_content.replace('{{VULNERABILITY_CARDS}}', vuln_cards_html)
                html_content = html_content.replace('{{CHART_DATA}}', chart_data_json)
                
                # Now process Jinja2-style template variables
                # Replace {% if ... %} ... {% endif %} blocks with content
                html_content = self._process_jinja_conditionals(html_content)
                
                # Replace {{ vuln.xxx }} style variables
                html_content = self._process_jinja_variables(html_content)
            else:
                # Use inline template if template file doesn't exist
                html_content = f"""<!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Vulnerability Report</title>
                    <style>
                        :root {{
            --primary-color: #1a3a5f;
            --secondary-color: #2c7be5;
            --accent-color: #e63757;
            --light-color: #f9fbfd;
            --dark-color: #12263f;
            --success-color: #00d97e;
            --warning-color: #f6c343;
            --danger-color: #e63757;
            --critical-color: #c81e1e;
            --info-color: #39afd1;
            --border-radius: 8px;
            --box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
            --transition: all 0.2s ease-in-out;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #495057;
            background-color: #f5f7fa;
            margin: 0;
            padding: 0;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0;
            background-color: transparent;
        }}
        
        header {{
            background: linear-gradient(135deg, var(--primary-color) 0%, #2c5282 100%);
            color: white;
            padding: 2.5rem 2rem;
            text-align: left;
            margin-bottom: 2rem;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
        }}
        
        header h1 {{
            color: white;
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}
        
        header p {{
            opacity: 0.85;
            font-size: 1rem;
        }}
        
        section {{
            background-color: white;
            border-radius: var(--border-radius);
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--box-shadow);
        }}
        
        h1, h2, h3, h4 {{
            color: var(--dark-color);
            margin-bottom: 1.25rem;
            font-weight: 600;
        }}
        
        h2 {{
            font-size: 1.75rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid #e9ecef;
            margin-bottom: 1.5rem;
        }}
        
        h3 {{
            font-size: 1.25rem;
        }}
        
        h4 {{
            font-size: 1.1rem;
            margin-bottom: 0.75rem;
        }}
        
        p {{
            margin-bottom: 1rem;
        }}
        
        a {{
            color: var(--secondary-color);
            text-decoration: none;
            transition: var(--transition);
        }}
        
        a:hover {{
            color: #1a5cbf;
            text-decoration: underline;
        }}
        
        .scan-info p {{
            margin-bottom: 0.75rem;
        }}
        
        .scan-info strong {{
            display: inline-block;
            min-width: 120px;
            color: var(--dark-color);
        }}
        
        .summary-section {{
            display: flex;
            justify-content: space-between;
            margin: 1.5rem 0;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        
        .summary-card {{
            flex: 1;
            min-width: 160px;
            background-color: white;
            border-radius: var(--border-radius);
            padding: 1.5rem;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
            text-align: center;
            transition: var(--transition);
            border: 1px solid #e9ecef;
        }}
        
        .summary-card:hover {{
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
        }}
        
        .summary-card h3 {{
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.75rem;
            color: #6c757d;
        }}
        
        .summary-card .count {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            line-height: 1;
        }}
        
        .critical {{ color: var(--critical-color); }}
        .high {{ color: var(--danger-color); }}
        .medium {{ color: var(--warning-color); }}
        .low {{ color: var(--info-color); }}
        .info {{ color: var(--success-color); }}
        
        .vulnerabilities {{
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }}
        
        .vuln-card {{
            background-color: white;
            border-radius: var(--border-radius);
            overflow: hidden;
            box-shadow: var(--box-shadow);
            border: 1px solid #e9ecef;
            transition: var(--transition);
        }}
        
        .vuln-card:hover {{
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
        }}
        
        .vuln-header {{
            padding: 1.25rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: white;
            font-weight: 600;
        }}
        
        .vuln-header.critical {{ background: linear-gradient(to right, var(--critical-color), #e74c3c); }}
        .vuln-header.high {{ background: linear-gradient(to right, var(--danger-color), #f05b78); }}
        .vuln-header.medium {{ background: linear-gradient(to right, var(--warning-color), #fad776); color: #664d03; }}
        .vuln-header.low {{ background: linear-gradient(to right, var(--info-color), #5bc0de); }}
        .vuln-header.info {{ background: linear-gradient(to right, var(--success-color), #39da8a); }}
        
        .vuln-content {{
            padding: 1.75rem;
        }}
        
        .severity-badge {{
            padding: 0.35rem 0.75rem;
            border-radius: 50px;
            font-weight: 600;
            font-size: 0.8rem;
            display: inline-block;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .severity-badge.critical {{ background-color: rgba(200, 30, 30, 0.1); color: var(--critical-color); }}
        .severity-badge.high {{ background-color: rgba(230, 55, 87, 0.1); color: var(--danger-color); }}
        .severity-badge.medium {{ background-color: rgba(246, 195, 67, 0.1); color: #997404; }}
        .severity-badge.low {{ background-color: rgba(57, 175, 209, 0.1); color: var(--info-color); }}
        .severity-badge.info {{ background-color: rgba(0, 217, 126, 0.1); color: var(--success-color); }}
        
        .vuln-details, .vuln-risk, .remediation-info, .details-section {{
            margin-bottom: 1.75rem;
            padding: 1.5rem;
            border-radius: var(--border-radius);
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
        }}
        
        .vuln-details p, .vuln-risk p, .remediation-info p, .details-section p {{
            margin-bottom: 0.75rem;
        }}
        
        .vuln-details p:last-child, .vuln-risk p:last-child, .remediation-info p:last-child, .details-section p:last-child {{
            margin-bottom: 0;
        }}
        
        .vuln-details strong, .vuln-risk strong, .remediation-info strong, .details-section strong {{
            color: var(--dark-color);
        }}
        
        .cvss-info, .cwe-info, .exploit-info, .impact-info {{
            margin-bottom: 1.5rem;
            padding: 1.25rem;
            border-radius: var(--border-radius);
            border-left: 4px solid transparent;
        }}
        
        .cvss-info {{ background-color: #e9f7fe; border-left-color: var(--info-color); }}
        .cwe-info {{ background-color: #f1f8ff; border-left-color: var(--secondary-color); }}
        .exploit-info {{ background-color: #fff8e6; border-left-color: var(--warning-color); }}
        .impact-info {{ background-color: #f6f8fa; border-left-color: #6c757d; }}
        .remediation-info {{ background-color: #e6ffed; border-left-color: var(--success-color); }}
        
        pre {{
            background-color: #f6f8fa;
            padding: 1rem;
            border-radius: var(--border-radius);
            overflow-x: auto;
            font-size: 0.9rem;
            border: 1px solid #e9ecef;
            margin: 1rem 0;
        }}
        
        code {{
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background-color: #f6f8fa;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.9rem;
            color: #e83e8c;
            border: 1px solid #e9ecef;
        }}
        
        .cwe-link {{
            display: inline-block;
            margin-top: 0.75rem;
            color: var(--secondary-color);
            text-decoration: none;
            font-weight: 500;
        }}
        
        .cwe-link:hover {{
            text-decoration: underline;
        }}
        
        footer {{
            text-align: center;
            margin-top: 2rem;
            padding: 1.5rem;
            color: #6c757d;
            font-size: 0.9rem;
            background-color: white;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
        }}
        
        /* Card styling fixes */
        .card {{
            margin-bottom: 1.5rem;
            border-radius: var(--border-radius);
            overflow: hidden;
            box-shadow: var(--box-shadow);
            border: 1px solid #e9ecef;
            transition: var(--transition);
        }}
        
        .card:hover {{
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
        }}
        
        .card-header {{
            padding: 1.25rem 1.5rem;
            font-weight: 600;
        }}
        
        .card-title {{
            margin: 0;
            font-size: 1.25rem;
        }}
        
        .bg-info {{
            background: linear-gradient(to right, var(--info-color), #5bc0de);
        }}
        
        .text-white {{
            color: white;
        }}
        
        .border-info {{
            border-color: var(--info-color);
        }}
        
        /* Responsive adjustments */
        @media (max-width: 768px) {{
            .container {{
                margin: 1rem;
                width: auto;
            }}
            
            .summary-card {{
                min-width: 140px;
            }}
            
            .summary-section {{
                gap: 0.75rem;
            }}
            
            .vuln-content {{
                padding: 1.25rem;
            }}
            
            .vuln-details, .vuln-risk, .remediation-info, .details-section {{
                padding: 1.25rem;
            }}
        }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <header>
                            <h1>Web Vulnerability Scan Report</h1>
                            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        </header>
                        
                        <section class="scan-info">
                            <h2>Scan Information</h2>
                            <p><strong>Start Time:</strong> {scan_info['start_time']}</p>
                            <p><strong>End Time:</strong> {scan_info['end_time']}</p>
                            <p><strong>Duration:</strong> {scan_info['duration_seconds']} seconds</p>
                            <p><strong>Target URLs:</strong> {', '.join(scan_info['target_urls'])}</p>
                        </section>
                        
                        <section class="summary">
                            <h2>Vulnerability Summary</h2>
                            <div class="summary-section">
                                <div class="summary-card">
                                    <h3>Total Vulnerabilities</h3>
                                    <div class="count">{len(self.vulnerabilities)}</div>
                                </div>
                                <div class="summary-card">
                                    <h3>Critical</h3>
                                    <div class="count critical">{severity_counts.get('CRITICAL', 0)}</div>
                                </div>
                                <div class="summary-card">
                                    <h3>High</h3>
                                    <div class="count high">{severity_counts.get('HIGH', 0)}</div>
                                </div>
                                <div class="summary-card">
                                    <h3>Medium</h3>
                                    <div class="count medium">{severity_counts.get('MEDIUM', 0)}</div>
                                </div>
                                <div class="summary-card">
                                    <h3>Low</h3>
                                    <div class="count low">{severity_counts.get('LOW', 0)}</div>
                                </div>
                                <div class="summary-card">
                                    <h3>Info</h3>
                                    <div class="count info">{severity_counts.get('INFO', 0)}</div>
                                </div>
                            </div>
                        </section>
                        
                        <section class="vulnerabilities">
                            <h2>Detected Vulnerabilities</h2>
                            {vuln_cards_html}
                        </section>
                        
                        <footer>
                            <p>Report generated by Web Vulnerability Scanner</p>
                        </footer>
                    </div>
                </body>
                </html>
                """
            
            # Write HTML report to file
            with open(html_file, 'w') as f:
                f.write(html_content)
            
            if self.logger:
                self.logger.info(f"HTML report saved to {html_file}")
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error generating HTML report: {e}")
        
        # Generate CSV report if format is set to 'all'
        if self.report_format.lower() == 'all':
            self._generate_csv_report(scan_duration, severity_counts)
        
    def _generate_cwe_html(self, vuln):
        """Generate HTML for CWE information"""
        cwe = vuln.get('cwe')
        if not cwe:
            return ""
            
        return f"""
        <div class="cwe-info">
            <h4>CWE Information</h4>
            <p><strong>{cwe.get('id', 'Unknown')}:</strong> {cwe.get('name', 'Unknown')}</p>
            <a href="{cwe.get('link', '#')}" class="cwe-link" target="_blank">Learn more about this vulnerability type</a>
        </div>
        """
        # Create a complete HTML report with actual content
        html_content = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Web Vulnerability Scan Report</title>
        <style>
            :root {
                --primary-color: #2c3e50;
                --secondary-color: #34495e;
                --accent-color: #3498db;
                --light-bg: #f8f9fa;
                --border-color: #e9ecef;
                --text-color: #333;
                --text-light: #6c757d;
                --critical: #dc3545;
                --high: #fd7e14;
                --medium: #ffc107;
                --low: #28a745;
                --info: #17a2b8;
                
                /* New colors for enhanced report */
                --cvss-bg: #e9f7fe;
                --exploit-bg: #fff8e6;
                --remediation-bg: #e6ffed;
                --impact-bg: #f6f8fa;
                --cwe-bg: #f1f8ff;
            }
            
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                line-height: 1.6;
                color: var(--text-color);
                background-color: var(--light-bg);
            }}
            
            .header {{
                background-color: var(--primary-color);
                color: white;
                padding: 2rem 0;
                margin-bottom: 2rem;
            }}
            
            .container {{
                width: 100%;
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 1rem;
            }}
            
            h1, h2, h3, h4 {{
                margin-bottom: 1rem;
                font-weight: 600;
            }}
            
            p {{
                margin-bottom: 1rem;
            }}
            
            .summary-card {{
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                padding: 1.5rem;
                margin-bottom: 2rem;
            }}
            
            .summary-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                gap: 1.5rem;
                margin: 1.5rem 0;
            }}
            
            .summary-item {{
                background-color: var(--light-bg);
                padding: 1rem;
                border-radius: 6px;
            }}
            
            .summary-item h4 {{
                font-size: 0.9rem;
                color: var(--text-light);
                margin-bottom: 0.5rem;
            }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 1.5rem 0;
            }}
            
            th {{
                background-color: var(--light-bg);
                text-align: left;
                padding: 1rem;
            }}
            
            td {{
                padding: 1rem;
                border-bottom: 1px solid var(--border-color);
            }}
            
            tr:last-child td {{
                border-bottom: none;
            }}
            
            tr:hover td {{
                background-color: var(--light-bg);
            }}
            
            .severity {{
                display: inline-block;
                padding: 0.35rem 0.75rem;
                border-radius: 50px;
                color: white;
                font-weight: 600;
                font-size: 0.8rem;
                text-transform: uppercase;
            }}
            
            .severity.CRITICAL {{
                background-color: var(--critical);
            }}
            
            .severity.HIGH {{
                background-color: var(--high);
            }}
            
            .severity.MEDIUM {{
                background-color: var(--medium);
                color: #212529;
            }}
            
            .severity.LOW {{
                background-color: var(--low);
            }}
            
            .severity.INFO {{
                background-color: var(--info);
            }}
            
            .vulnerability {{
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                margin-bottom: 1.5rem;
                overflow: hidden;
            }}
            
            .vulnerability-header {{
                padding: 1.25rem;
                border-bottom: 1px solid var(--border-color);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            
            .vulnerability-body {{
                padding: 1.25rem;
            }}
            
            /* Enhanced styling for vulnerability details */
            .cvss-score {
                font-weight: bold;
                padding: 0.2rem 0.5rem;
                border-radius: 3px;
                background-color: var(--cvss-bg);
            }
            
            .exploit-info, .impact-info, .remediation, .cwe-info {
                margin-top: 1rem;
                padding: 1rem;
                border-radius: 6px;
            }
            
            .exploit-info {
                background-color: var(--exploit-bg);
            }
            
            .impact-info {
                background-color: var(--impact-bg);
            }
            
            .remediation {
                background-color: var(--remediation-bg);
            }
            
            .cwe-info {
                background-color: var(--cwe-bg);
            }
            
            .cwe-link {
                display: inline-block;
                margin-top: 0.5rem;
                color: var(--accent-color);
                text-decoration: none;
            }
            
            .cwe-link:hover {
                text-decoration: underline;
            }
            .vulnerability.CRITICAL {{
                border-left: 5px solid var(--critical);
            }}
            
            .vulnerability.HIGH {{
                border-left: 5px solid var(--high);
            }}
            
            .vulnerability.MEDIUM {{
                border-left: 5px solid var(--medium);
            }}
            
            .vulnerability.LOW {{
                border-left: 5px solid var(--low);
            }}
            
            .vulnerability.INFO {{
                border-left: 5px solid var(--info);
            }}
            
            .details {{
                background-color: var(--light-bg);
                border-radius: 6px;
                padding: 1.25rem;
                margin-top: 1rem;
            }}
            
            .details h4 {{
                margin-bottom: 0.75rem;
                font-size: 1rem;
            }}
            
            .url {{
                word-break: break-all;
                font-family: monospace;
                background-color: var(--light-bg);
                padding: 0.25rem 0.5rem;
                border-radius: 4px;
            }}
            
            .footer {{
                text-align: center;
                margin-top: 3rem;
                color: var(--text-light);
                font-size: 0.9rem;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="container">
                <h1>Web Vulnerability Scan Report</h1>
            </div>
        </div>
        
        <div class="container">
            <div class="summary-card">
                <h2>Scan Summary</h2>
                
                <div class="summary-grid">
                    <div class="summary-item">
                        <h4>Start Time</h4>
                        <p>{self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <div class="summary-item">
                        <h4>End Time</h4>
                        <p>{self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <div class="summary-item">
                        <h4>Duration</h4>
                        <p>{scan_duration:.2f} seconds</p>
                    </div>
                    
                    <div class="summary-item">
                        <h4>Target URLs</h4>
                        <p>{self._get_target_urls_string()}</p>
                    </div>
                </div>
                
                <h3>Vulnerability Summary</h3>
                <p><strong>Total Vulnerabilities:</strong> {len(self.vulnerabilities)}</p>
                
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                    </tr>"""
        
        # Add severity counts to the HTML
        for severity, count in severity_counts.items():
            if count > 0:
                html_content += f"""
                    <tr>
                        <td><span class="severity {{severity}}">{severity}</span></td>
                        <td>{count}</td>
                    </tr>"""
        
        html_content += """
                </table>
            </div>
            
            <h2>Vulnerabilities</h2>"""
        
        # Add vulnerabilities to the HTML
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            vuln_type = vuln.get('type', 'Unknown')
            url = vuln.get('url', 'Unknown URL')
            description = vuln.get('description', 'No description')
            details = vuln.get('details', {})
            
            html_content += f"""
            <div class="vulnerability {severity}">
                <div class="vulnerability-header">
                    <h3>{vuln_type}</h3>
                    <span class="severity {severity}">{severity}</span>
                </div>
                
                <div class="vulnerability-body">
                    <p><strong>URL:</strong> <span class="url">{url}</span></p>
                    <p><strong>Description:</strong> {description}</p>
                    
                    <!-- Add CVSS Score -->
                    <p><strong>CVSS Score:</strong> <span class="cvss-score">{vuln.get('cvss_score', 'N/A')}</span></p>
                    <p><strong>CVSS Vector:</strong> <code>{vuln.get('cvss_vector', 'N/A')}</code></p>
                    
                    <!-- Add CWE Information -->
                    {self._generate_cwe_html(vuln)}
                    
                    <!-- Add Exploit Information -->
                    <div class="exploit-info">
                        <h4>Exploit Information</h4>
                        <p>{vuln.get('exploit_info', 'No exploit information available.')}</p>
                    </div>
                    
                    <!-- Add Impact Information -->
                    <div class="impact-info">
                        <h4>Impact</h4>
                        <p>{vuln.get('impact', 'Impact information not available.')}</p>
                    </div>
                    
                    <!-- Add Remediation Guidance -->
                    <div class="remediation">
                        <h4>Remediation</h4>
                        <p>{vuln.get('remediation', 'Remediation guidance not available.')}</p>
                    </div>
                    
                    <div class="details">
                        <h4>Technical Details</h4>"""
            
            # Add vulnerability details
            details = vuln.get('details', {})
            details_html = ''
            if isinstance(details, dict):
                for key, value in details.items():
                    details_html += f"""
                        <p><strong>{key}:</strong> {str(value)}</p>"""
            else:
                details_html = f"""
                        <p>{str(details)}</p>"""
            vuln_cards_html += details_html
            
            vuln_cards_html += """
                    </div>
                </div>
            </div>"""
        
        # Close the HTML document
        html_content += f"""
            <div class="footer">
                <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
    </body>
    </html>"""
        
        # Save the HTML report
        report_file = self.report_file.replace('.json', '.html')
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            if self.logger:
                self.logger.info(f"HTML report saved to {report_file}")
            return report_file
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error saving HTML report: {e}")
            return None
    
    def _get_target_urls_string(self):
        """Get a string representation of target URLs"""
        if hasattr(self, 'target_urls') and self.target_urls:
            return ", ".join(self.target_urls)
        elif self.scanner and hasattr(self.scanner, 'target_urls'):
            return ", ".join(self.scanner.target_urls)
        return "None"
    
    def _generate_csv_report(self, scan_duration, severity_counts):
        """Generate a CSV report"""
        import csv
        
        report_file = self.report_file.replace('.json', '.csv')
        
        try:
            with open(report_file, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow(['Severity', 'Type', 'URL', 'Description', 'Details'])
                
                # Write vulnerabilities
                for vuln in self.vulnerabilities:
                    severity = vuln.get('severity', 'UNKNOWN')
                    vuln_type = vuln.get('type', 'Unknown')
                    url = vuln.get('url', 'Unknown URL')
                    description = vuln.get('description', 'No description')
                    details = json.dumps(vuln.get('details', {}))
                    
                    writer.writerow([severity, vuln_type, url, description, details])
            
            self.logger.info(f"CSV report saved to {report_file}")
        except Exception as e:
            self.logger.error(f"Error saving CSV report: {e}")

    def generate_report(self, format=None):
        """Generate the vulnerability report in the specified format"""
        if format:
            self.report_format = format.lower()
        
        # Calculate scan duration
        if self.scan_end_time and self.scan_start_time:
            scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        else:
            # If scan times are not set, use current time
            if not self.scan_start_time:
                self.scan_start_time = datetime.now() - timedelta(seconds=1)
            if not self.scan_end_time:
                self.scan_end_time = datetime.now()
            scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        # Generate reports based on format
        report_files = []
        
        # Always generate JSON report as base
        json_file = self._generate_json_report(scan_duration, self._count_vulnerabilities_by_severity())
        if json_file:
            report_files.append(json_file)
        
        # Generate additional formats if requested
        if self.report_format == 'html' or self.report_format == 'all':
            html_file = self._generate_html_report(scan_duration, self._count_vulnerabilities_by_severity())
            if html_file:
                report_files.append(html_file)
        
        if self.report_format == 'csv' or self.report_format == 'all':
            csv_file = self._generate_csv_report(scan_duration, self._count_vulnerabilities_by_severity())
            if csv_file:
                report_files.append(csv_file)
        
        return report_files

    def _count_vulnerabilities_by_severity(self):
        """Count vulnerabilities by severity"""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return severity_counts


##############################################