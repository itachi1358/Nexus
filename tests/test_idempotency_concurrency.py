"""The killer test: one packet delivered by three bridges at the same instant settles
exactly once. Plus tamper rejection, crypto round trip, and two regression tests."""
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import pytest

from upi_mesh import bridge, crypto, idempotency, ledger, main, mesh
from upi_mesh.models import PaymentInstruction

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


@pytest.fixture(autouse=True)
def clear_cache():
    idempotency.clear()


def balance(vpa: str) -> Decimal:
    return next(a["balance"] for a in ledger.list_accounts() if a["vpa"] == vpa)


def test_single_packet_delivered_by_three_bridges_settles_exactly_once():
    alice_before, bob_before = balance("alice@demo"), balance("bob@demo")
    packet = mesh.create_packet("alice@demo", "bob@demo", Decimal("100.00"), "1234", 5)

    start = threading.Barrier(3, timeout=5)  # release all three threads at once

    def deliver(node):
        start.wait()
        return bridge.ingest(packet, node, 3)["outcome"]

    with ThreadPoolExecutor(3) as pool:
        outcomes = list(pool.map(deliver, ["bridge-0", "bridge-1", "bridge-2"]))

    assert sorted(outcomes) == ["DUPLICATE_DROPPED", "DUPLICATE_DROPPED", "SETTLED"]
    assert balance("alice@demo") == alice_before - Decimal("100.00")
    assert balance("bob@demo") == bob_before + Decimal("100.00")


def test_same_packet_uploaded_by_three_online_phones_settles_once():
    extra = ["phone-stranger2", "phone-stranger3"]  # online alongside phone-bridge
    mesh.reset()
    for d in extra:
        mesh.set_internet(d, True)
    try:
        mesh.inject("phone-alice", mesh.create_packet("alice@demo", "bob@demo", Decimal("1.00"), "1234", 5))
        mesh.gossip_once()
        outcomes = sorted(r["outcome"] for r in main.mesh_flush()["results"])
    finally:
        for d in extra:
            mesh.set_internet(d, False)
        mesh.reset()

    assert outcomes == ["DUPLICATE_DROPPED", "DUPLICATE_DROPPED", "SETTLED"]


def test_tampered_ciphertext_is_rejected():
    packet = mesh.create_packet("alice@demo", "bob@demo", Decimal("50.00"), "1234", 5)
    ct, mid = packet.ciphertext, len(packet.ciphertext) // 2
    packet.ciphertext = ct[:mid] + ("B" if ct[mid] == "A" else "A") + ct[mid + 1:]

    assert bridge.ingest(packet, "bridge-x", 1)["outcome"] == "INVALID"


def test_encrypt_decrypt_round_trip():
    original = PaymentInstruction(sender_vpa="alice@demo", receiver_vpa="bob@demo",
                                  amount=Decimal("123.45"), pin_hash="abcdef",
                                  nonce="nonce-1", signed_at=1_700_000_000_000)

    assert crypto.decrypt(crypto.encrypt(original, crypto.public_key)) == original


def test_same_packet_spelled_differently_in_base64_is_still_a_duplicate():
    # Flip a spare bit in the last base64 character: different text, identical bytes.
    # Hashing the text instead of the bytes let this settle twice.
    packet = next(p for p in (mesh.create_packet("alice@demo", "bob@demo", Decimal(n), "1234", 5)
                              for n in range(1, 50)) if p.ciphertext.endswith("="))
    body = packet.ciphertext.rstrip("=")
    respelled = (body[:-1] + B64_ALPHABET[B64_ALPHABET.index(body[-1]) ^ 1]
                 + packet.ciphertext[len(body):])

    assert bridge.ingest(packet, "bridge-a", 1)["outcome"] == "SETTLED"
    copy = packet.model_copy(update={"ciphertext": respelled})
    assert bridge.ingest(copy, "bridge-b", 1)["outcome"] == "DUPLICATE_DROPPED"


def test_failed_settlement_releases_claim_so_retry_settles(monkeypatch):
    packet = mesh.create_packet("alice@demo", "bob@demo", Decimal("10.00"), "1234", 5)
    real_settle = ledger.settle

    def fail_once(*args):
        monkeypatch.setattr(ledger, "settle", real_settle)
        raise RuntimeError("db blip")

    monkeypatch.setattr(ledger, "settle", fail_once)

    assert bridge.ingest(packet, "bridge-a", 1)["outcome"] == "INVALID"
    assert bridge.ingest(packet, "bridge-a", 1)["outcome"] == "SETTLED"
