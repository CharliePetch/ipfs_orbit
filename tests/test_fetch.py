# tests/test_fetch.py
"""
Tests for GET /fetch/{cid} — the station retrieving ARBITRARY CIDs over its
own IPFS connection on behalf of the owner's paired devices, so a delegate
never has to lean on a rate-limited public gateway.

/content/{cid} (tests/test_content.py) is the local-only, own-content-only
sibling; the helpers here are borrowed from it. What matters for /fetch:

  1. Owner-only, same ML-DSA signatures as /content.
  2. Blast-radius controls actually bite: the enable flag, the size gate
     (checked before any stream is opened), the concurrency cap.
  3. Pinning, when opted in, happens AFTER a complete stream — never before
     the first byte, and never after a partial (Range) read.
  4. The worker slot is released on every path, success or failure.
  5. The size probe uses files/stat (object/stat is gone in kubo 0.28).

IPFS is never contacted: the stat probe, the network stream and pin/add are
all stubbed at the ipfs_client module boundary.
"""

import threading

import pytest

import cipher_station.config as config_mod
import cipher_station.ipfs_client as ipfs_mod
import cipher_station.main as main_mod
from cipher_station import pqcrypto
from cipher_station.ipfs_client import IPFSError, IPFSUnavailable
from tests.test_content import (  # noqa: F401  (owner_device is a fixture)
    FakeUpstream,
    call_app,
    owner_device,
    signed_headers,
)

CID_REMOTE = "QmRmte" + "f" * 40
BODY = b"third-party-bytes-" * 500


def auth(dev, cid, method="GET"):
    return signed_headers(f"/fetch/{cid}", dev["uid"], dev["device_uid"], dev["sk"], method=method)


@pytest.fixture
def fake_ipfs(monkeypatch):
    """
    Stub the three IPFS touch points and record every call, so a test can
    assert e.g. that an oversized CID never had a stream opened for it.
    """
    calls = {"stat": [], "stream": [], "pin": []}
    state = {
        "size": len(BODY),
        "stat_raises": None,
        "stream_raises": None,
        "response": None,
    }

    def fake_stat(cid, *, timeout=None, retry=True):
        calls["stat"].append({"cid": cid, "timeout": timeout, "retry": retry})
        if state["stat_raises"] is not None:
            raise state["stat_raises"]
        return {"Hash": cid, "CumulativeSize": state["size"]}

    def fake_stream(cid, *, range_header=None, timeout=None):
        calls["stream"].append({"cid": cid, "range": range_header, "timeout": timeout})
        if state["stream_raises"] is not None:
            raise state["stream_raises"]
        return state["response"] or FakeUpstream(BODY)

    def fake_pin(cid, *, timeout=None):
        calls["pin"].append(cid)

    monkeypatch.setattr(ipfs_mod, "ipfs_object_stat", fake_stat)
    monkeypatch.setattr(ipfs_mod, "ipfs_open_network_stream", fake_stream)
    monkeypatch.setattr(ipfs_mod, "ipfs_pin_add", fake_pin)
    return {"calls": calls, "state": state}


@pytest.fixture
def fresh_slots(monkeypatch):
    """A private semaphore per test so cap assertions cannot bleed across tests."""
    sem = threading.BoundedSemaphore(2)
    monkeypatch.setattr(main_mod, "_fetch_slots", sem)
    return sem


def slots_free(sem: threading.BoundedSemaphore) -> int:
    return sem._value  # noqa: SLF001 — only way to observe a semaphore's count


# ---------------------------------------------------------------------------
# 1. Auth
# ---------------------------------------------------------------------------

class TestAuth:
    def test_missing_headers_are_rejected_before_ipfs(self, fake_ipfs, fresh_slots):
        # Same convention as /content: absent auth headers fail validation (422).
        status, _, _ = call_app("GET", f"/fetch/{CID_REMOTE}")
        assert status == 422
        assert fake_ipfs["calls"]["stat"] == []
        assert fake_ipfs["calls"]["stream"] == []

    def test_bad_signature_is_401_before_ipfs(self, owner_device, fake_ipfs, fresh_slots):
        _, wrong_sk = pqcrypto.generate_mldsa_keypair()
        hdrs = signed_headers(f"/fetch/{CID_REMOTE}", owner_device["uid"], owner_device["device_uid"], wrong_sk)
        status, _, _ = call_app("GET", f"/fetch/{CID_REMOTE}", hdrs)
        assert status == 401
        assert fake_ipfs["calls"]["stat"] == []

    def test_owner_device_gets_bytes(self, owner_device, fake_ipfs, fresh_slots):
        status, headers, body = call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert status == 200
        assert body == BODY
        assert headers["content-length"] == str(len(BODY))
        assert headers["accept-ranges"] == "bytes"
        assert [c["cid"] for c in fake_ipfs["calls"]["stream"]] == [CID_REMOTE]


# ---------------------------------------------------------------------------
# 2. Blast-radius controls
# ---------------------------------------------------------------------------

class TestControls:
    def test_disabled_is_a_plain_404(self, owner_device, fake_ipfs, fresh_slots, monkeypatch):
        monkeypatch.setattr(config_mod, "FETCH_ENABLED", False)
        status, _, _ = call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert status == 404
        assert fake_ipfs["calls"]["stat"] == []

    def test_non_cid_is_400_and_never_probed(self, owner_device, fake_ipfs, fresh_slots):
        bad = "not-a-cid"
        status, _, _ = call_app("GET", f"/fetch/{bad}", auth(owner_device, bad))
        assert status == 400
        assert fake_ipfs["calls"]["stat"] == []
        assert slots_free(fresh_slots) == 2

    def test_oversized_is_413_and_no_stream_is_opened(self, owner_device, fake_ipfs, fresh_slots, monkeypatch):
        monkeypatch.setattr(config_mod, "FETCH_MAX_BYTES", 10)
        status, _, _ = call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert status == 413
        assert fake_ipfs["calls"]["stream"] == []
        assert slots_free(fresh_slots) == 2

    def test_size_probe_uses_fetch_timeout_without_retry(self, owner_device, fake_ipfs, fresh_slots, monkeypatch):
        monkeypatch.setattr(config_mod, "FETCH_TIMEOUT", 77)
        call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert fake_ipfs["calls"]["stat"] == [{"cid": CID_REMOTE, "timeout": 77, "retry": False}]

    def test_unresolvable_cid_is_404(self, owner_device, fake_ipfs, fresh_slots):
        fake_ipfs["state"]["stat_raises"] = IPFSError("timed out")
        status, _, _ = call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert status == 404
        assert fake_ipfs["calls"]["stream"] == []
        assert slots_free(fresh_slots) == 2

    def test_daemon_down_is_503_not_404(self, owner_device, fake_ipfs, fresh_slots):
        fake_ipfs["state"]["stat_raises"] = IPFSUnavailable("connection refused")
        status, _, _ = call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert status == 503
        assert slots_free(fresh_slots) == 2

    def test_stream_failure_is_504_and_releases_slot(self, owner_device, fake_ipfs, fresh_slots):
        fake_ipfs["state"]["stream_raises"] = IPFSError("gateway 504")
        status, _, _ = call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert status == 504
        assert slots_free(fresh_slots) == 2

    def test_concurrency_cap_returns_503_with_retry_after(self, owner_device, fake_ipfs, fresh_slots):
        # Occupy every slot as if two fetches were mid-DHT-walk.
        fresh_slots.acquire()
        fresh_slots.acquire()
        status, headers, _ = call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert status == 503
        assert headers["retry-after"] == "5"
        assert fake_ipfs["calls"]["stat"] == []
        fresh_slots.release()
        fresh_slots.release()

    def test_slot_released_after_successful_stream(self, owner_device, fake_ipfs, fresh_slots):
        status, _, body = call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert status == 200 and body == BODY
        assert slots_free(fresh_slots) == 2


# ---------------------------------------------------------------------------
# 3. Range + pinning
# ---------------------------------------------------------------------------

class TestRangeAndPin:
    def test_range_is_passed_through_and_206_mirrored(self, owner_device, fake_ipfs, fresh_slots):
        part = BODY[10:20]
        fake_ipfs["state"]["response"] = FakeUpstream(
            part, status=206,
            headers={"Content-Length": "10", "Content-Range": f"bytes 10-19/{len(BODY)}"},
        )
        hdrs = {**auth(owner_device, CID_REMOTE), "range": "bytes=10-19"}
        status, headers, body = call_app("GET", f"/fetch/{CID_REMOTE}", hdrs)
        assert status == 206
        assert body == part
        assert headers["content-range"] == f"bytes 10-19/{len(BODY)}"
        assert fake_ipfs["calls"]["stream"][0]["range"] == "bytes=10-19"

    def test_unsatisfiable_range_is_416_and_releases_slot(self, owner_device, fake_ipfs, fresh_slots):
        upstream = FakeUpstream(b"", status=416, headers={})
        fake_ipfs["state"]["response"] = upstream
        status, _, _ = call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert status == 416
        assert upstream.closed
        assert slots_free(fresh_slots) == 2

    def test_no_pin_by_default(self, owner_device, fake_ipfs, fresh_slots):
        call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert fake_ipfs["calls"]["pin"] == []

    def test_pin_happens_after_full_stream(self, owner_device, fake_ipfs, fresh_slots, monkeypatch):
        monkeypatch.setattr(config_mod, "FETCH_PIN", True)
        order = []
        fake_ipfs["calls"]["pin"] = order  # pin appends the cid here

        class Recording(FakeUpstream):
            def iter_content(self, chunk_size=1):
                for chunk in super().iter_content(chunk_size):
                    order.append("chunk")
                    yield chunk

        fake_ipfs["state"]["response"] = Recording(BODY)
        status, _, body = call_app("GET", f"/fetch/{CID_REMOTE}", auth(owner_device, CID_REMOTE))
        assert status == 200 and body == BODY
        assert order[-1] == CID_REMOTE, "pin must be the LAST thing, after every chunk"
        assert order.count(CID_REMOTE) == 1
        assert slots_free(fresh_slots) == 2

    def test_partial_read_is_never_pinned(self, owner_device, fake_ipfs, fresh_slots, monkeypatch):
        monkeypatch.setattr(config_mod, "FETCH_PIN", True)
        fake_ipfs["state"]["response"] = FakeUpstream(
            BODY[:10], status=206,
            headers={"Content-Length": "10", "Content-Range": f"bytes 0-9/{len(BODY)}"},
        )
        hdrs = {**auth(owner_device, CID_REMOTE), "range": "bytes=0-9"}
        status, _, _ = call_app("GET", f"/fetch/{CID_REMOTE}", hdrs)
        assert status == 206
        assert fake_ipfs["calls"]["pin"] == []


# ---------------------------------------------------------------------------
# 4. ipfs_client: the probe itself
# ---------------------------------------------------------------------------

class TestObjectStat:
    def test_uses_files_stat_with_ipfs_path(self, monkeypatch):
        """kubo 0.28 removed object/stat; the probe must hit files/stat instead."""
        seen = {}

        class R:
            def raise_for_status(self):
                pass

            def json(self):
                return {"CumulativeSize": 42}

        def fake_post(url, params=None, timeout=None):
            seen.update(url=url, params=params, timeout=timeout)
            return R()

        monkeypatch.setattr(ipfs_mod.requests, "post", fake_post)
        out = ipfs_mod.ipfs_object_stat(CID_REMOTE, timeout=9, retry=False)
        assert out["CumulativeSize"] == 42
        assert seen["url"].endswith("/api/v0/files/stat")
        assert "object/stat" not in seen["url"]
        assert seen["params"] == {"arg": f"/ipfs/{CID_REMOTE}"}
        assert seen["timeout"] == 9

    def test_no_retry_path_maps_connection_error(self, monkeypatch):
        def boom(*a, **k):
            raise ipfs_mod.requests.exceptions.ConnectionError("refused")

        monkeypatch.setattr(ipfs_mod.requests, "post", boom)
        with pytest.raises(IPFSUnavailable):
            ipfs_mod.ipfs_object_stat(CID_REMOTE, retry=False)

    def test_no_retry_path_does_not_retry_timeouts(self, monkeypatch):
        attempts = []

        def slow(*a, **k):
            attempts.append(1)
            raise ipfs_mod.requests.exceptions.Timeout("dht walk")

        monkeypatch.setattr(ipfs_mod.requests, "post", slow)
        monkeypatch.setattr(ipfs_mod.time, "sleep", lambda s: None)
        with pytest.raises(IPFSError):
            ipfs_mod.ipfs_object_stat(CID_REMOTE, retry=False)
        assert len(attempts) == 1
