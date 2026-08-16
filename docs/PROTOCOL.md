# Guardian status protocol

The Guardian publishes a signed, read-only status projection for Melloa. Melloa receives only the public verification key and status file. It never receives the private key, transition CLI, repository authority, firewall authority, or service-control credentials.

## Envelope

Protocol version `1.0.0` uses an Ed25519 signature over:

```text
"MELLOA-GUARDIAN-STATUS-V1\0" || UTF8(JSON payload)
```

The outer JSON document contains `envelope_version`, `algorithm`, `key_id`, unpadded base64url `payload`, and unpadded base64url `signature`. The payload contains the installation ID, one of the six required modes, a monotonic sequence, UTC transition time, qualified reason code, and the previous receipt hash after genesis.

Receipt hashes use:

```text
SHA256("MELLOA-GUARDIAN-RECEIPT-V1\0" || payload || "\0" || signature || "\0" || key_id)
```

The append-only JSONL journal is authoritative. `status.json` is an atomic projection; `guardianctl status` reconciles it from the last valid journal record after an interrupted write.

## State machine

Startup progresses `stopped → offline → read-only → no-actions → normal`. Restriction can move back through explicit safe transitions. `recovery` is entered only from `stopped` and exits only to `stopped`, preventing accidental restoration of ordinary authority.

## Failure behavior

- Invalid signatures, malformed payloads, unsupported modes, broken hash chains, and broad private-key permissions fail closed.
- The main Melloa runtime treats missing or unauthentic status as no authority.
- Mode publication does not grant Melloa a command channel into the Guardian.
