# cipher_station/panel/__init__.py
"""
Cipher Station admin panel.

A web GUI served by its OWN 127.0.0.1-only uvicorn listener (default port
8444) inside the station process — never by the public :8443 app. Access
requires the per-boot bearer token written to <data_dir>/panel_token (0600).
See app.py for the panel ASGI app, router.py for the routes, guard.py for the
token + localhost checks, service.py for status/config logic, and drive.py
for the CipherVault-compatible drive client.
"""

from cipher_station.panel.app import create_panel_app

__all__ = ["create_panel_app"]
