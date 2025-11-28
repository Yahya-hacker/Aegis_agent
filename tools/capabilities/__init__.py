"""
Aegis v8.0 Capability Modules

Full-Spectrum CTF & Red Team Operations:
- crypto_engine: Cryptography analysis (Ciphey, hashid, john)
- reverse_engine: Reverse engineering (strings, objdump, radare2, gdb)
- forensics_lab: Digital forensics (exiftool, binwalk, steghide, volatility)
- pwn_exploiter: Binary exploitation (pwntools, checksec)
- network_sentry: Network analysis (tshark, tcpdump)
"""

from .crypto_engine import CryptoEngine, get_crypto_engine
from .reverse_engine import ReverseEngine, get_reverse_engine
from .forensics_lab import ForensicsLab, get_forensics_lab
from .pwn_exploiter import PwnExploiter, get_pwn_exploiter
from .network_sentry import NetworkSentry, get_network_sentry

__all__ = [
    'CryptoEngine',
    'ReverseEngine',
    'ForensicsLab',
    'PwnExploiter',
    'NetworkSentry',
    'get_crypto_engine',
    'get_reverse_engine',
    'get_forensics_lab',
    'get_pwn_exploiter',
    'get_network_sentry',
]
