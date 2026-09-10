# cipher_station/panel/__init__.py
"""
Cipher Station admin panel.

A localhost-only web GUI served by the station's own FastAPI app under
``/admin``. See router.py for the routes, guard.py for the localhost check,
service.py for status/config logic, and drive.py for the CipherVault-compatible
drive client.
"""

from cipher_station.panel.router import panel_router

__all__ = ["panel_router"]
