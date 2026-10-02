"""The full server-side pipeline for one packet arriving from a bridge node:

  1. Hash the ciphertext.
  2. Claim that hash in the idempotency cache. Already claimed -> duplicate, drop it.
  3. Decrypt with the server's private key. Fails -> tampered or junk, reject.
  4. Freshness check: reject if signed_at is too old (replay protection).
  5. Hand off to the ledger for the actual debit/credit.
"""
import logging
import os
import time

from . import crypto, idempotency, ledger
from .models import MeshPacket

log = logging.getLogger(__name__)

MAX_AGE_SECONDS = int(os.environ.get("UPI_MESH_PACKET_MAX_AGE_SECONDS", 86400))
CLOCK_SKEW_SECONDS = 300


def _result(outcome: str, packet_hash: str, reason: str | None = None,
            transaction_id: int | None = None) -> dict:
    return {"outcome": outcome, "packetHash": packet_hash, "reason": reason,
            "transactionId": transaction_id}


def ingest(packet: MeshPacket, bridge_node_id: str, hop_count: int) -> dict:
    try:
        packet_hash = crypto.hash_ciphertext(packet.ciphertext)
    except ValueError:  # not valid base64
        return _result("INVALID", "?", "bad_encoding")

    # ---- Idempotency gate ----
    if not idempotency.claim(packet_hash):
        log.info("DUPLICATE packet %s... from bridge %s — dropped", packet_hash[:12], bridge_node_id)
        return _result("DUPLICATE_DROPPED", packet_hash)

    # ---- Decrypt ----
    try:
        instruction = crypto.decrypt(packet.ciphertext)
    except Exception as e:
        log.warning("Decryption failed for packet %s...: %r", packet_hash[:12], e)
        return _result("INVALID", packet_hash, "decryption_failed")

    # ---- Freshness check (replay protection) ----
    age_seconds = time.time() - instruction.signed_at / 1000
    if age_seconds > MAX_AGE_SECONDS:
        log.warning("Packet %s... too old (%.0fs), rejected", packet_hash[:12], age_seconds)
        return _result("INVALID", packet_hash, "stale_packet")
    if age_seconds < -CLOCK_SKEW_SECONDS:
        return _result("INVALID", packet_hash, "future_dated")

    # ---- Settle ----
    try:
        tx_id, status = ledger.settle(instruction, packet_hash, bridge_node_id, hop_count)
    except Exception as e:
        # Give the claim back so a retry can settle after a transient failure. A true
        # double-settle is still blocked by the DB's unique packet_hash.
        idempotency.release(packet_hash)
        log.error("Ingestion error: %s", e, exc_info=True)
        return _result("INVALID", packet_hash, f"internal_error: {e}")
    return _result(status, packet_hash, transaction_id=tx_id)
