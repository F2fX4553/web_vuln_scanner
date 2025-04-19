#!/usr/bin/env python3
"""
Logger utility for the Web Vulnerability Scanner
"""

import logging
import os
import datetime
from colorama import init, Fore, Style

# Initialize colorama
init()

class Logger:
    def __init__(self, log_level=logging.INFO, log_file=None):
        """Initialize the logger with the specified log level and file"""
        self.logger = logging.getLogger('WebVulnScanner')
        self.logger.setLevel(log_level)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Create file handler if log_file is specified
        if log_file:
            # Create logs directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
                
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def info(self, message):
        """Log an info message"""
        self.logger.info(message)
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")
    
    def warning(self, message):
        """Log a warning message"""
        self.logger.warning(message)
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
    
    def error(self, message):
        """Log an error message"""
        self.logger.error(message)
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
    
    def critical(self, message):
        """Log a critical message"""
        self.logger.critical(message)
        print(f"{Fore.RED}{Style.BRIGHT}[CRITICAL]{Style.RESET_ALL} {message}")
    
    def debug(self, message):
        """Log a debug message"""
        self.logger.debug(message)
        if logging.DEBUG >= self.logger.level:
            print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} {message}")
    
    def success(self, message):
        """Log a success message (custom level)"""
        self.logger.info(f"SUCCESS: {message}")
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
    
    def vulnerability(self, vuln_type, severity, message):
        """Log a vulnerability with severity color coding"""
        severity_colors = {
            'LOW': Fore.BLUE,
            'MEDIUM': Fore.YELLOW,
            'HIGH': Fore.RED,
            'CRITICAL': Fore.RED + Style.BRIGHT
        }
        
        color = severity_colors.get(severity.upper(), Fore.WHITE)
        self.logger.warning(f"VULNERABILITY: [{severity}] {vuln_type} - {message}")
        print(f"{color}[{severity}] {vuln_type}{Style.RESET_ALL}: {message}")