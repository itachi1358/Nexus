"""HTTP layer: the REST API and the dashboard.

  /api/server-key                  -> simulated senders fetch the server's public key
  /api/demo/send, /api/mesh/*      -> simulator endpoints (inject, gossip, flush, reset)
  /api/bridge/ingest               -> THE production endpoint a real bridge phone would hit
  /api/accounts, /api/transactions -> for the dashboard

Run:  python -m upi_mesh.main     then open http://localhost:8080
"""
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse

from . import bridge, crypto, idempotency, ledger, mesh
from .models import DemoSendRequest, MeshPacket

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Server RSA keypair generated (2048-bit). Public key fingerprint: %s...",
             crypto.public_key_b64[:32])

    async def evict_every_minute():
        while True:
            await asyncio.sleep(60)
            idempotency.evict_expired()

    task = asyncio.create_task(evict_every_minute())
    yield
    task.cancel()


app = FastAPI(title="UPI Offline Mesh", lifespan=lifespan)


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).with_name("dashboard.html"))


# ---------------------------------------------------------------- key

@app.get("/api/server-key")
def server_key():
    return {"publicKey": crypto.public_key_b64,
            "algorithm": "RSA-2048 / OAEP-SHA256",
            "hybridScheme": "RSA-OAEP encrypts an AES-256-GCM session key"}


# ---------------------------------------------------------------- demo

@app.post("/api/demo/send")
def demo_send(req: DemoSendRequest):
    """Build a packet on the server (simulating the sender's phone) and inject it
    into the mesh at the given device."""
    packet = mesh.create_packet(req.sender_vpa, req.receiver_vpa, req.amount, req.pin,
                                mesh.DEFAULT_TTL if req.ttl is None else req.ttl)
    start_device = req.start_device or "phone-alice"
    try:
        mesh.inject(start_device, packet)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"packetId": packet.packet_id,
            "ciphertextPreview": packet.ciphertext[:64] + "...",
            "ttl": packet.ttl,
            "injectedAt": start_device}


# ------------------------------------------------------------ mesh sim

@app.get("/api/mesh/state")
def mesh_state():
    return {"devices": mesh.state(), "idempotencyCacheSize": idempotency.size()}


@app.post("/api/mesh/gossip")
def mesh_gossip():
    transfers, counts = mesh.gossip_once()
    return {"transfers": transfers, "deviceCounts": counts}


@app.put("/api/mesh/devices/{device_id}/internet")
def set_device_internet(device_id: str, has_internet: bool = Body(embed=True, alias="hasInternet")):
    """Switch a phone's 4G on or off. With several phones online, one uplink delivers
    the same packet several times at once: the idempotency demo."""
    try:
        mesh.set_internet(device_id, has_internet)
    except ValueError as e:
        raise HTTPException(404, str(e))
    return {"deviceId": device_id, "hasInternet": has_internet}


@app.post("/api/mesh/flush")
def mesh_flush():
    """Every phone with internet uploads everything it holds, at the same moment.
    Uploads run in parallel, so if several online phones hold the same packet the
    server gets concurrent copies, and only one may settle."""
    uploads = mesh.bridge_uploads()

    def upload(item):
        node, pkt = item
        r = bridge.ingest(pkt, node, mesh.DEFAULT_TTL - pkt.ttl)
        return {"bridgeNode": node, "packetId": pkt.packet_id[:8], "outcome": r["outcome"],
                "reason": r["reason"] or "", "transactionId": r["transactionId"] or -1}

    with ThreadPoolExecutor() as pool:
        results = list(pool.map(upload, uploads))
    return {"uploadsAttempted": len(uploads), "results": results}


@app.post("/api/mesh/reset")
def mesh_reset():
    mesh.reset()
    idempotency.clear()
    return {"status": "mesh and idempotency cache cleared"}


# -------------------------------------------------------------- bridge

@app.post("/api/bridge/ingest")
def bridge_ingest(packet: MeshPacket,
                  x_bridge_node_id: str = Header("unknown"),
                  x_hop_count: int = Header(0)):
    """THE PRODUCTION ENDPOINT. A real bridge phone POSTs here whenever it has
    internet and is holding mesh packets."""
    return bridge.ingest(packet, x_bridge_node_id, x_hop_count)


# ------------------------------------------------------------ accounts

@app.get("/api/accounts")
def accounts():
    return ledger.list_accounts()


@app.get("/api/transactions")
def transactions():
    return ledger.recent_transactions()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=8080)
