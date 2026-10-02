"""The ledger: accounts and the settled-transaction log, in an in-memory SQLite DB.

Simulated bank accounts. In a real system they live in the bank's core; for the demo
we own the ledger. Money is stored as integer paise.
"""
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from decimal import Decimal

from .models import PaymentInstruction

log = logging.getLogger(__name__)

CENT = Decimal("0.01")

# ponytail: one connection behind one global lock serializes all DB work, so two
# settlements can never interleave. Swap to Postgres + row locks if throughput matters.
_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.row_factory = sqlite3.Row
_lock = threading.Lock()

_db.executescript("""
CREATE TABLE accounts (
    vpa         TEXT PRIMARY KEY,          -- Virtual Payment Address, e.g. alice@demo
    holder_name TEXT NOT NULL,
    balance     INTEGER NOT NULL,          -- paise
    version     INTEGER NOT NULL DEFAULT 0 -- bumped on every write
);
CREATE TABLE transactions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_hash    TEXT NOT NULL UNIQUE,   -- idempotency key; DB backstop if the cache layer fails
    sender_vpa     TEXT NOT NULL,
    receiver_vpa   TEXT NOT NULL,
    amount         INTEGER NOT NULL,       -- paise
    signed_at      TEXT NOT NULL,          -- when the sender signed it (offline)
    settled_at     TEXT NOT NULL,          -- when the backend processed it
    bridge_node_id TEXT NOT NULL,          -- which mesh node finally delivered it
    hop_count      INTEGER NOT NULL,       -- how many devices it passed through
    status         TEXT NOT NULL CHECK (status IN ('SETTLED', 'REJECTED'))
);
INSERT INTO accounts (vpa, holder_name, balance) VALUES
    ('alice@demo', 'Alice', 500000),
    ('bob@demo',   'Bob',   100000),
    ('carol@demo', 'Carol', 250000),
    ('dave@demo',  'Dave',   50000);
""")
log.info("Seeded 4 demo accounts")


def _rupees(paise: int) -> Decimal:
    return Decimal(paise).scaleb(-2)


def _iso(epoch_ms: int) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000, timezone.utc).isoformat()


def settle(instruction: PaymentInstruction, packet_hash: str,
           bridge_node_id: str, hop_count: int) -> tuple[int, str]:
    """Debit the sender, credit the receiver and write the ledger row in ONE DB
    transaction: either all of it happens or none of it does.

    Insufficient balance is recorded as a REJECTED row. Returns (transaction id, status).
    """
    amount = int(instruction.amount.quantize(CENT) * 100)
    if amount <= 0:
        raise ValueError("Amount must be positive")
    sender_vpa, receiver_vpa = instruction.sender_vpa, instruction.receiver_vpa

    with _lock, _db:  # `with _db` commits on success, rolls back on any exception
        sender = _db.execute("SELECT balance FROM accounts WHERE vpa = ?", (sender_vpa,)).fetchone()
        if sender is None:
            raise ValueError(f"Unknown sender VPA: {sender_vpa}")
        if _db.execute("SELECT 1 FROM accounts WHERE vpa = ?", (receiver_vpa,)).fetchone() is None:
            raise ValueError(f"Unknown receiver VPA: {receiver_vpa}")

        status = "SETTLED" if sender["balance"] >= amount else "REJECTED"
        if status == "SETTLED":
            _db.execute("UPDATE accounts SET balance = balance - ?, version = version + 1 WHERE vpa = ?",
                        (amount, sender_vpa))
            _db.execute("UPDATE accounts SET balance = balance + ?, version = version + 1 WHERE vpa = ?",
                        (amount, receiver_vpa))
        else:
            log.warning("Insufficient balance: %s has ₹%s, tried to send ₹%s",
                        sender_vpa, _rupees(sender["balance"]), _rupees(amount))

        tx_id = _db.execute(
            "INSERT INTO transactions (packet_hash, sender_vpa, receiver_vpa, amount, signed_at,"
            " settled_at, bridge_node_id, hop_count, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (packet_hash, sender_vpa, receiver_vpa, amount, _iso(instruction.signed_at),
             datetime.now(timezone.utc).isoformat(), bridge_node_id, hop_count, status),
        ).lastrowid

    if status == "SETTLED":
        log.info("SETTLED ₹%s from %s to %s (packetHash=%s..., bridge=%s, hops=%d)",
                 _rupees(amount), sender_vpa, receiver_vpa, packet_hash[:12], bridge_node_id, hop_count)
    return tx_id, status


def list_accounts() -> list[dict]:
    with _lock:
        rows = _db.execute("SELECT * FROM accounts").fetchall()
    return [{"vpa": r["vpa"], "holderName": r["holder_name"], "balance": _rupees(r["balance"]),
             "version": r["version"]} for r in rows]


def recent_transactions(limit: int = 20) -> list[dict]:
    with _lock:
        rows = _db.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{"id": r["id"], "packetHash": r["packet_hash"], "senderVpa": r["sender_vpa"],
             "receiverVpa": r["receiver_vpa"], "amount": _rupees(r["amount"]),
             "signedAt": r["signed_at"], "settledAt": r["settled_at"],
             "bridgeNodeId": r["bridge_node_id"], "hopCount": r["hop_count"],
             "status": r["status"]} for r in rows]
