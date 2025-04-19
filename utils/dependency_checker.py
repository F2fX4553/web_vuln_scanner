#!/usr/bin/env python3
"""
Dependency checker for the Web Vulnerability Scanner
"""

import sys
import subprocess
import importlib

def check_dependencies():
    """Check and install required packages"""
    required_packages = ['tqdm', 'bs4', 'colorama', 'requests']
    missing_packages = []
    
    for package in required_packages:
        try:
            importlib.import_module(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"Missing required packages: {', '.join(missing_packages)}")
        install = input("Would you like to install them now? (y/n): ").lower()
        if install == 'y':
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
                print("Dependencies installed successfully!")
                # Reload modules
                for package in missing_packages:
                    globals()[package] = importlib.import_module(package)
                return True
            except Exception as e:
                print(f"Error installing dependencies: {e}")
                print("Please install the required packages manually using:")
                print(f"pip install {' '.join(missing_packages)}")
                return False
        else:
            print("Please install the required packages manually using:")
            print(f"pip install {' '.join(missing_packages)}")
            return False
    return True