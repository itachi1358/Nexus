"""Wire formats. JSON keys are camelCase, matching the original Java service."""
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class MeshPacket(CamelModel):
    """What hops from phone to phone over Bluetooth.

    Intermediate phones can read the outer fields (packet_id, ttl, created_at) because
    they need them for routing and gossip dedup. They cannot read `ciphertext`: only
    the server's private key opens it.

    A malicious intermediate can rewrite packet_id or created_at. That's why the server
    dedupes on a hash of the ciphertext, never on packet_id.
    """
    packet_id: str = Field(min_length=1)   # UUID, used by intermediates for gossip dedup
    ttl: int = Field(0, ge=0)              # hops remaining; each hop decrements it
    created_at: int                        # epoch millis, when the sender created the packet
    ciphertext: str = Field(min_length=1)  # base64(RSA-encrypted AES key + IV + AES-GCM ciphertext)


class PaymentInstruction(CamelModel):
    """The payload inside MeshPacket.ciphertext.

    nonce:     unique per payment, so two identical ₹100 payments still produce
               different ciphertexts (and different idempotency hashes).
    signed_at: lets the server reject stale packets (replay window).
    pin_hash:  a real system would verify the UPI PIN with the bank. Here it is
               only recorded for realism; nothing checks it.
    """
    sender_vpa: str
    receiver_vpa: str
    amount: Decimal
    pin_hash: str
    nonce: str
    signed_at: int


class DemoSendRequest(CamelModel):
    sender_vpa: str
    receiver_vpa: str
    amount: Decimal
    pin: str
    ttl: int | None = None
    start_device: str | None = None
