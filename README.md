# Melloa Guardian

This repository is the independently controlled safety, restriction, shutdown, and recovery plane for Melloa.

The Guardian is deliberately separate from the main Melloa runtime. It owns host-level emergency modes, workload stop, network isolation, credential revocation, and recovery entry points. Melloa and Melli may observe Guardian status through a narrow protocol, but they must not be able to modify, redeploy, disable, or grant authority to the Guardian.

> **Source status:** This repository does not currently include a source license. Its contents are publicly readable, but public visibility does not grant permission to use, modify, or redistribute them. Do not describe the Guardian as open source unless the owner selects and adds explicit license terms.

The implementation-independent constraints live in Melloa's
[trust boundaries](https://github.com/melloa-project/melloa/blob/main/docs/trust-boundaries.md),
and the read-only integration is defined by the
[Guardian protocol contract](https://github.com/melloa-project/melloa/blob/main/docs/contracts/guardian-protocol.md).

## Safe first run

From the repository root, use this project first as a disposable protocol drill, not as a host-control deployment:

```bash
make check
make preview-state
```

The source build requires Go 1.24 or newer, as declared in `go.mod`. `preview-state` builds the CLI,
prints the owner-visible `stopped` and `offline` receipts, removes its temporary signing material,
and leaves only the signed status and public key under `state/local-preview/`. Follow
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) to hand those two public paths to Melloa and clean them
up from this repository when finished.

Do not connect the drill to real systemd units, firewall rules, credential revocation, recovery keys, or host inventory. Those values are owner deployment state and belong in a separately reviewed deployment plan.

## M0 implementation

The main repository defines the narrow Guardian protocol and consumes it through a read-only
verification adapter. This repository implements the independently controlled side of protocol
version `1.0.0`:

- all six required modes and a deterministic state machine;
- Ed25519-signed read-only status consumed by Melloa;
- chained, append-only transition receipts;
- atomic status projection with journal reconciliation;
- strict private-key permissions and no model or Melloa dependency.

Read [`docs/TRUST_BOUNDARY.md`](docs/TRUST_BOUNDARY.md) for the invariant, [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the signed status contract, and [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for the disposable drill.
