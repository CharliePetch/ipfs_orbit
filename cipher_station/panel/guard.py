# cipher_station/panel/guard.py
"""
Localhost-only guard for the admin panel.

Every /admin route depends on ``require_localhost``. The check inspects the
ACTUAL socket peer address from the ASGI scope (``request.client``) — never a
header — so X-Forwarded-For / X-Real-IP cannot spoof it through a proxy.
Remote use is an SSH tunnel: ``ssh -L 8443:localhost:8443 user@station``.
"""

from fastapi import HTTPException, Request

# Loopback peers only. "::ffff:127.0.0.1" is IPv4 loopback seen through an
# IPv6 dual-stack socket.
_LOOPBACK = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


def is_loopback_address(host: str | None) -> bool:
    if not host:
        return False
    if host in _LOOPBACK:
        return True
    # Any 127.0.0.0/8 address is loopback.
    return host.startswith("127.")


async def require_localhost(request: Request) -> None:
    client = request.client
    if client is None or not is_loopback_address(client.host):
        raise HTTPException(
            status_code=403,
            detail="Admin panel is localhost-only. Use an SSH tunnel: "
                   "ssh -L 8443:localhost:8443 user@station",
        )
