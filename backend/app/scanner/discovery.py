"""
Active network discovery via nmap — legacy module.

NOTE: The scanner pipeline now uses app.scanner.stages.discovery directly.
This module is kept for backward compatibility with any code that imported it,
but new code should import from app.scanner.stages.discovery.
"""
# Re-export the new discovery module's sweep function for compatibility
from app.scanner.stages.discovery import sweep, PassiveArpListener  # noqa: F401
