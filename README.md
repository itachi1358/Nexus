# UPI Offline Mesh — Demo (Python)

A FastAPI backend that demonstrates **offline UPI payments routed through a Bluetooth-style mesh network**. You're in a basement with zero connectivity. You send your friend ₹500. Your phone encrypts the payment and broadcasts it to nearby phones. The packet hops from device to device until *some* phone walks outside, gets 4G, and quietly uploads it to this backend. The backend decrypts it, deduplicates it, and settles it.

This repo is the **server side** of that system, plus a software simulator of the mesh, so you can demo the whole flow on one laptop without any Bluetooth hardware.


---

## What this demo proves

1. **A payment can travel from sender to backend through untrusted phones**, and none of them can read it or alter it in transit. (Hybrid RSA + AES-GCM encryption.)
2. **Even if the same payment reaches the backend through several bridge phones at the same instant, it settles exactly once.** (An atomic claim on the ciphertext hash.)
3. **A tampered or replayed packet is rejected** before it touches the ledger.

---

## How to run it

**Prerequisite:** Python 3.10 or newer (`python --version`).

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# Mac / Linux:  source .venv/bin/activate
pip install -r requirements.txt

python -m upi_mesh.main
```

Open **http://localhost:8080** for the dashboard. Interactive API docs are at http://localhost:8080/docs. Stop the server with `Ctrl+C`.

The server listens on localhost only. To let real phones on your network reach it, run `uvicorn upi_mesh.main:app --host 0.0.0.0 --port 8080`.

### Run the tests

```bash
python -m pytest
```

---

## The demo flow

The dashboard walks through the whole pipeline.

**1. Compose a payment.** Pick sender, receiver, amount and PIN, then click **Seal and inject**. The server plays the sender's phone:
- it builds a `PaymentInstruction` with a unique nonce and the current time;
- it encrypts it with the server's RSA public key;
- it wraps it in a `MeshPacket` with TTL 5;
- it hands the packet to `phone-alice`.

**2. Run a gossip round.** Click **Gossip round**. Every phone holding a packet copies it to every other phone in "Bluetooth range" (in the simulator, that's everyone), and TTL drops by one per hop.

**3. Uplink.** Click **Uplink**. Every phone with 4G uploads everything it holds. By default only `phone-bridge` is online. The backend then:
1. hashes the ciphertext (SHA-256);
2. claims the hash in the idempotency cache;
3. decrypts the packet;
4. checks it is fresh;
5. debits and credits the accounts in one DB transaction.

Watch the account balances and the ledger update.

**4. Idempotency.** Under the mesh is a row of **4G** switches, one per phone.
1. Turn on two more phones, for example `stranger2` and `stranger3`.
2. Inject a payment, run a gossip round, then click **Uplink**.

Three phones now upload the same packet at the same moment. You'll see:
- three packets fly to the backend together: one green (settled), two amber (duplicates dropped);
- one new ledger row;
- balances that move once;
- an event-log line summarising the dedup.

Clicking **Uplink** again sends all three copies once more; every one comes back `DUPLICATE_DROPPED`.

The same scenario runs as a test:

```bash
python -m pytest -k three_online_phones
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SENDER PHONE (offline)                          │
│  PaymentInstruction { sender, receiver, amount, pinHash, nonce, time }  │
│              │                                                          │
│              ▼ encrypt with server's RSA public key                     │
│   MeshPacket { packetId, ttl, createdAt, ciphertext }                   │
└──────────────────────────────────────┬──────────────────────────────────┘
                                       │ Bluetooth gossip
                                       ▼
        ┌─────────┐  hop   ┌─────────┐  hop   ┌─────────┐
        │stranger1│ ─────▶ │stranger2│ ─────▶ │ bridge  │ ◀── walks outside
        └─────────┘        └─────────┘        └────┬────┘     gets 4G
                                                   │
                                                   ▼ HTTPS POST
┌─────────────────────────────────────────────────────────────────────────┐
│                        FASTAPI BACKEND (this project)                   │
│                                                                         │
│  /api/bridge/ingest                                                     │
│       │                                                                 │
│       ▼                                                                 │
│  [1] SHA-256 of the decoded ciphertext bytes                            │
│       ▼                                                                 │
│  [2] idempotency.claim(hash)   ◀── atomic check-and-set (≈ Redis SETNX).│
│       │                            Duplicates are dropped here.         │
│       ▼                                                                 │
│  [3] crypto.decrypt(ciphertext)                                         │
│       │   (RSA-OAEP unwraps the AES key; AES-GCM decrypts the payload   │
│       │    AND verifies the auth tag, so tampering raises)              │
│       ▼                                                                 │
│  [4] Freshness check: signedAt within the last 24h                      │
│       ▼                                                                 │
│  [5] ledger.settle(): debit sender, credit receiver, write ledger row   │
│      in one SQLite transaction                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## The three hard problems and how they're solved

### 1. Untrusted intermediates

A stranger's phone is carrying your payment. How do you stop them reading or changing the amount?

**Hybrid encryption (RSA-OAEP + AES-256-GCM).** RSA alone can only encrypt a few hundred bytes, so each packet works like this:
1. Generate a fresh AES-256 key for this packet.
2. Encrypt the JSON with AES-GCM.
3. Encrypt only the AES key with RSA-OAEP.

The wire format is `[256-byte RSA-encrypted key][12-byte IV][ciphertext + 16-byte GCM tag]`, base64-encoded. GCM is authenticated encryption: flip one bit anywhere and decryption fails. See [upi_mesh/crypto.py](upi_mesh/crypto.py).

### 2. The duplicate storm

Three bridge phones hold the same packet. They walk outside at the same instant and all POST within milliseconds of each other. Processed naively, the sender is debited ₹1500 instead of ₹500.

**An atomic claim on the ciphertext hash.** The first thing the server does is hash the ciphertext and try to claim that hash:

```python
# idempotency.py
with _lock:
    if packet_hash in _seen:
        return False          # duplicate
    _seen[packet_hash] = time.monotonic()
    return True               # first claimer
```

Exactly one caller wins. Everyone else gets `DUPLICATE_DROPPED` before any decryption happens. In production this becomes Redis `SET key NX EX 86400`.

**Why hash the ciphertext?**
- `packetId` can be rewritten by any intermediate.
- Decrypting first would waste RSA work on duplicates.

The hash covers the **decoded bytes**, not the base64 text. A base64 decoder accepts several spellings of the same bytes, so hashing the text would let one payment be re-spelled and settle twice.

**Backstop:** `transactions.packet_hash` is `UNIQUE`. If the cache ever fails, the database rejects a second settlement of the same hash.

### 3. Replay attacks

- **Timestamp:** the encrypted payload carries `signedAt`, and the server rejects anything older than 24 hours. Nobody can change `signedAt` without breaking the GCM tag.
- **Nonce:** the payload also carries a random nonce. If Alice really does send Bob ₹100 twice, the nonces differ, so the hashes differ and both payments settle. A *replay* of one packet is the same bytes, so the idempotency cache catches it.

---

## File-by-file walkthrough

```
├── requirements.txt              FastAPI, uvicorn, cryptography, pytest
├── upi_mesh/
│   ├── __init__.py               Logging setup
│   ├── main.py                   FastAPI app: every REST endpoint + the dashboard + cache eviction
│   ├── models.py                 MeshPacket (wire format), PaymentInstruction (decrypted payload)
│   ├── crypto.py                 RSA keypair, RSA-OAEP + AES-256-GCM encrypt/decrypt, ciphertext hash
│   ├── idempotency.py            dict + lock = process-local Redis SETNX, with TTL eviction
│   ├── bridge.py                 THE pipeline: hash → claim → decrypt → freshness → settle
│   ├── ledger.py                 In-memory SQLite: accounts, transaction log, settle()
│   ├── mesh.py                   Sender phone (create_packet), virtual devices, gossip
│   └── dashboard.html            The interactive demo UI
└── tests/
    └── test_idempotency_concurrency.py
```

Where each Java class went:

| Java | Python |
|---|---|
| `UpiMeshApplication`, `AppConfig` (`@EnableScheduling`) | `main.py` (`__main__` block; lifespan task evicts the cache every 60s) |
| `ApiController`, `DashboardController` | `main.py` |
| `ServerKeyHolder`, `HybridCryptoService` | `crypto.py` |
| `MeshPacket`, `PaymentInstruction`, `DemoSendRequest` | `models.py` (pydantic) |
| `Account`, `Transaction`, both repositories, `SettlementService` | `ledger.py` (stdlib `sqlite3`) |
| `IdempotencyService` | `idempotency.py` |
| `BridgeIngestionService` | `bridge.py` |
| `DemoService` | `mesh.create_packet()`; account seeding is in `ledger.py` |
| `MeshSimulatorService`, `VirtualDevice` | `mesh.py` |
| `application.properties` | env vars `UPI_MESH_IDEMPOTENCY_TTL_SECONDS`, `UPI_MESH_PACKET_MAX_AGE_SECONDS` (default 86400) |

---

## API reference

| Method | Path | What it does |
|---|---|---|
| GET | `/` | Dashboard |
| GET | `/api/server-key` | Server's RSA public key (base64) |
| GET | `/api/accounts` | All accounts and balances |
| GET | `/api/transactions` | Last 20 transactions |
| GET | `/api/mesh/state` | State of every virtual device |
| POST | `/api/demo/send` | Simulate the sender phone: encrypt + inject a packet |
| POST | `/api/mesh/gossip` | Run one gossip round |
| PUT | `/api/mesh/devices/{deviceId}/internet` | Switch a phone's 4G on or off. Body: `{"hasInternet": true}` |
| POST | `/api/mesh/flush` | Every phone with 4G uploads to the backend (in parallel) |
| POST | `/api/mesh/reset` | Clear the mesh and the idempotency cache |
| POST | `/api/bridge/ingest` | **The production endpoint.** Real bridges POST here |

### Request format for `/api/bridge/ingest`

```http
POST /api/bridge/ingest
Content-Type: application/json
X-Bridge-Node-Id: phone-bridge-42
X-Hop-Count: 3

{
  "packetId": "550e8400-e29b-41d4-a716-446655440000",
  "ttl": 2,
  "createdAt": 1730000000000,
  "ciphertext": "base64-encoded-RSA-and-AES-blob"
}
```

Response:

```json
{
  "outcome": "SETTLED",
  "packetHash": "a3f8c9...",
  "reason": null,
  "transactionId": 42
}
```

`outcome` is one of:

| Outcome | Meaning |
|---|---|
| `SETTLED` | Money moved |
| `REJECTED` | Insufficient balance; recorded in the ledger, no money moved |
| `DUPLICATE_DROPPED` | Already claimed by an earlier delivery |
| `INVALID` | Rejected; `reason` says why: `bad_encoding`, `decryption_failed`, `stale_packet`, `future_dated` or `internal_error: …` |

---

## Tests

`python -m pytest` runs:

- **`test_single_packet_delivered_by_three_bridges_settles_exactly_once`**: the headline test. Three threads deliver one packet at the same instant. Exactly one `SETTLED`, two `DUPLICATE_DROPPED`, and the balance moves once.
- **`test_same_packet_uploaded_by_three_online_phones_settles_once`**: the dashboard's idempotency demo. Three phones go online, gossip spreads one packet to all of them, and one uplink settles it once.
- **`test_tampered_ciphertext_is_rejected`**: flip a character, get `INVALID`.
- **`test_encrypt_decrypt_round_trip`**: the hybrid encryption round-trips.
- **`test_same_packet_spelled_differently_in_base64_is_still_a_duplicate`**: regression test for the double-settle bug in the Java version.
- **`test_failed_settlement_releases_claim_so_retry_settles`**: regression test for the lost-payment bug in the Java version.

---

## Differences from the Java version

Same endpoints, JSON shapes, dashboard and flow. The changes:

**Bugs fixed (each server-side fix has a regression test):**
1. **Double settlement.** Java hashed the base64 *text*. One packet re-spelled in base64 (for example, padding stripped) got a new hash and settled again; the DB unique index didn't catch it either. This version hashes the decoded bytes.
2. **Lost payments.** Java never released the idempotency claim when settlement failed, so every retry for 24h was `DUPLICATE_DROPPED`. This version releases it.
3. **Stored XSS.** Java put the `X-Bridge-Node-Id` header into the dashboard with `innerHTML`. The dashboard now escapes server data.
4. **Wrong outcome.** Java reported `SETTLED` for insufficient-balance payments that the ledger recorded as `REJECTED`. The outcome now says `REJECTED`.

**Platform swaps:**
- **Database:** H2 + JPA became stdlib `sqlite3`, still in-memory and wiped on restart. Money is stored as integer paise.
- **Locking:** JPA's `@Version` optimistic locking became one lock around all DB work. Settlements can't interleave; that's fine for a demo, but use Postgres row locks for real throughput.
- **Validation:** `/api/bridge/ingest` now validates the request body (malformed → 422). Java declared the constraints but never enforced them (no `@Valid`).
- **Not ported:** the H2 web console.

---

## What's NOT real (and what would change for production)

| In the demo | In production |
|---|---|
| In-memory SQLite | PostgreSQL / MySQL with replicas |
| dict + lock for idempotency | Redis `SET NX EX` |
| RSA keypair regenerated on every startup | Private key in an HSM / KMS; public key cached on devices |
| Server-side `mesh.create_packet()` | The same logic running on the phone |
| Software-simulated mesh | Real BLE GATT or Wi-Fi Direct |
| One service that owns the ledger | Integration with NPCI / a bank core |
| No auth on `/api/bridge/ingest` | Mutual TLS or signed bridge-node certificates |
| Seeded accounts, PIN never verified | KYC'd users, real VPAs, PIN verified by the bank |
| No rate limiting | Per-bridge rate limits, per-sender velocity checks |
| Logs to console | Structured logs to a SIEM, alerts on `INVALID` spikes |

---

## Honest limitations of the concept

These are inherent to "no internet anywhere in the chain", not implementation bugs:

1. **Anyone can create a payment from any account.** Encryption uses only the server's *public* key, which `/api/server-key` publishes. Anyone can build "alice@demo pays me ₹5000" and it settles. GCM stops intermediaries from *altering* a packet, but it says nothing about who *created* it. Nothing is signed (despite the `signedAt` name), and `pinHash` is never checked. **A real system needs a per-device signing key**, registered while online and ideally hardware-backed, with the server verifying a signature on every instruction.
2. **The receiver can't verify the sender has the funds.** A "₹500 sent" screen is an IOU. If the account is empty when the packet lands, it's `REJECTED` and the receiver has no recourse. This is why real offline UPI (UPI Lite) uses a pre-funded, hardware-backed wallet.
3. **A malicious sender can double-spend offline.** They send ₹500 to Bob in basement A and ₹500 to Carol in basement B. The first packet to reach the backend wins; the other is `REJECTED`.
4. **Bluetooth in real life is hard.** Background BLE on Android is heavily throttled, and iOS peripheral mode is locked down. Two strangers' phones reliably connecting while the apps aren't open is difficult and power-hungry. This demo skips the problem by simulating the mesh.
5. **Privacy and liability.** Strangers carry your encrypted payment. They can't read it, but the fact that it exists is metadata.

Pitch it honestly as **"mesh-routed deferred settlement"**, not "real-time offline UPI".

---

## Troubleshooting

- **`python` not found:** install Python 3.10+ from python.org (on Windows, `winget install Python.Python.3.12`).
- **Port 8080 already in use:** `uvicorn upi_mesh.main:app --port 8081`.
- **`ModuleNotFoundError: upi_mesh` in tests:** run `python -m pytest` from the project root, not bare `pytest`.

## License

Demo code, no license. Use it however you want for learning.
