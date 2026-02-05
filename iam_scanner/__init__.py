"""
IAM Privilege Escalation Scanner Package

A modular tool for scanning AWS IAM roles and users for privilege escalation vulnerabilities.
"""

__version__ = "2.0.0"
__author__ = "Security Automation"

from .scanners.base_scanner import IAMPrivEscScanner

__all__ = ['IAMPrivEscScanner']
