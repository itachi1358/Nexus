"""Simulated phones: the sender phone that builds packets, and the Bluetooth mesh.

Default scenario: 4 offline phones in a basement and 1 "bridge" phone that can
reach 4G. Every phone is in Bluetooth range of every other phone.
"""
import hashlib
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal

from . import crypto
from .models import MeshPacket, PaymentInstruction

log = logging.getLogger(__name__)

DEFAULT_TTL = 5


def create_packet(sender_vpa: str, receiver_vpa: str, amount: Decimal, pin: str, ttl: int) -> MeshPacket:
    """Simulates the sender's phone:
      1. Build a PaymentInstruction with a fresh nonce and signed_at timestamp.
      2. Encrypt it with the server's public key (hybrid RSA + AES).
      3. Wrap it in a MeshPacket with a TTL.

    On a real phone this same code runs with a public key cached during an earlier
    online session.
    """
    instruction = PaymentInstruction(
        sender_vpa=sender_vpa,
        receiver_vpa=receiver_vpa,
        amount=amount,
        pin_hash=hashlib.sha256(pin.encode()).hexdigest(),
        nonce=str(uuid.uuid4()),             # guarantees two identical payments differ
        signed_at=int(time.time() * 1000),   # for the freshness check
    )
    return MeshPacket(
        packet_id=str(uuid.uuid4()),
        ttl=ttl,
        created_at=int(time.time() * 1000),
        ciphertext=crypto.encrypt(instruction, crypto.public_key),
    )


@dataclass
class VirtualDevice:
    """One simulated phone and the packets it carries. On a real phone packets
    would move over BLE GATT characteristics."""
    device_id: str
    has_internet: bool
    held: dict[str, MeshPacket] = field(default_factory=dict)  # packet_id -> packet


devices = {d.device_id: d for d in (
    VirtualDevice("phone-alice", False),
    VirtualDevice("phone-stranger1", False),
    VirtualDevice("phone-stranger2", False),
    VirtualDevice("phone-stranger3", False),
    VirtualDevice("phone-bridge", True),
)}
_lock = threading.Lock()


def inject(device_id: str, packet: MeshPacket) -> None:
    """The sender drops a packet into the mesh by handing it to their own phone."""
    with _lock:
        device = devices.get(device_id)
        if device is None:
            raise ValueError(f"Unknown device: {device_id}")
        device.held.setdefault(packet.packet_id, packet)
    log.info("Packet %s injected at %s (TTL=%d)", packet.packet_id[:8], device_id, packet.ttl)


def set_internet(device_id: str, on: bool) -> None:
    """Switch a phone's mobile data on or off. Every phone with internet is a bridge:
    it uploads what it carries on the next uplink."""
    with _lock:
        device = devices.get(device_id)
        if device is None:
            raise ValueError(f"Unknown device: {device_id}")
        device.has_internet = on
    log.info("%s %s", device_id, "is online (4G)" if on else "went offline")


def gossip_once() -> tuple[int, dict[str, int]]:
    """One gossip round. Every device shares every packet it held at the START of the
    round with every other device; TTL drops by 1 per hop, and TTL-0 packets stay put.

    Real BLE gossip is pairwise, as people walk past each other. All-to-all in one
    round is a fast-forward of many pairwise rounds.
    """
    with _lock:
        snapshot = {d.device_id: list(d.held.values()) for d in devices.values()}
        transfers = 0
        for src in devices.values():
            for pkt in snapshot[src.device_id]:
                if pkt.ttl <= 0:
                    continue
                for dst in devices.values():
                    if dst is src or pkt.packet_id in dst.held:
                        continue
                    dst.held[pkt.packet_id] = pkt.model_copy(update={"ttl": pkt.ttl - 1})
                    transfers += 1
        counts = {d.device_id: len(d.held) for d in devices.values()}
    log.info("Gossip round complete: %d packet transfers", transfers)
    return transfers, counts


def state() -> list[dict]:
    with _lock:
        return [{"deviceId": d.device_id, "hasInternet": d.has_internet,
                 "packetCount": len(d.held), "packetIds": [pid[:8] for pid in d.held]}
                for d in devices.values()]


def bridge_uploads() -> list[tuple[str, MeshPacket]]:
    """(bridge device id, packet) for every packet held by a phone with internet:
    what gets uploaded the moment those phones reach connectivity."""
    with _lock:
        return [(d.device_id, p) for d in devices.values() if d.has_internet for p in d.held.values()]


def reset() -> None:
    with _lock:
        for d in devices.values():
            d.held.clear()
