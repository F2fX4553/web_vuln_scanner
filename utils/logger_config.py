#!/usr/bin/env python3
"""
Logger configuration for the Web Vulnerability Scanner
"""

import logging
import sys
import os
from colorama import Fore, Style

class VulnerabilityFilter(logging.Filter):
    def filter(self, record):
        # Only log warnings (vulnerabilities) and errors to the file
        return record.levelno >= logging.WARNING

def setup_logging():
    """Configure and set up logging"""
    # Configure two separate handlers
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(
        f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - %(levelname)s - %(message)s'))

    file_handler = logging.FileHandler(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanner.log"))
    file_handler.setLevel(logging.WARNING)  # Only warnings and above
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    file_handler.addFilter(VulnerabilityFilter())

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    return root_logger