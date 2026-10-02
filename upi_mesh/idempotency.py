"""In-memory idempotency cache. In production this is Redis `SET key NX EX <ttl>`:
the same semantics, shared across server instances.

The contract:
  - claim(hash) returns True on the first call and False on every later call
    (within the TTL window)
  - it is atomic: even if 100 threads claim the same hash at the same instant,
    exactly one gets True

This is what kills the "three bridges deliver at once" problem.
"""
import os
import threading
import time

TTL_SECONDS = int(os.environ.get("UPI_MESH_IDEMPOTENCY_TTL_SECONDS", 86400))

_seen: dict[str, float] = {}  # packet hash -> monotonic time it was claimed
_lock = threading.Lock()


def claim(packet_hash: str) -> bool:
    """True if this caller is first; False if the packet is a duplicate."""
    with _lock:
        if packet_hash in _seen:
            return False
        _seen[packet_hash] = time.monotonic()
        return True


def release(packet_hash: str) -> None:
    """Hand a claim back so a bridge can retry after a failed settlement."""
    with _lock:
        _seen.pop(packet_hash, None)


def size() -> int:
    return len(_seen)


def evict_expired() -> None:
    """Drop entries past their TTL so the cache doesn't grow forever (run every minute)."""
    cutoff = time.monotonic() - TTL_SECONDS
    with _lock:
        for h in [h for h, t in _seen.items() if t < cutoff]:
            del _seen[h]


def clear() -> None:
    """Test/demo helper."""
    with _lock:
        _seen.clear()
