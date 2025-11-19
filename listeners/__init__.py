# listeners/__init__.py
"""
Echo OOB (Out-of-Band) Correlator System

This module provides infrastructure for detecting delayed/blind vulnerabilities
through out-of-band channels like DNS, HTTP callbacks, and SMTP.
"""

from .dns_callback import get_oob_manager, OOBManager

__all__ = ['get_oob_manager', 'OOBManager']
