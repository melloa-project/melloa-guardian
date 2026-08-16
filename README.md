# Melloa Guardian

This repository is the independently controlled safety, restriction, shutdown, and recovery plane for Melloa.

The Guardian is deliberately separate from the main Melloa runtime. It owns host-level emergency modes, workload stop, network isolation, credential revocation, and recovery entry points. Melloa and Melli may observe Guardian status through a narrow protocol, but they must not be able to modify, redeploy, disable, or grant authority to the Guardian.

The authoritative architecture is currently maintained in [`melloa-project/melloa`](https://github.com/melloa-project/melloa), especially ADR-008, the control-plane specification, the security model, and the v0.2 decision record.

## M0 implementation

The main repository now defines the narrow Guardian protocol and a fake read-only adapter. This repository implements the independently controlled side of protocol version `1.0.0`:

- all six required modes and a deterministic state machine;
- Ed25519-signed read-only status consumed by Melloa;
- chained, append-only transition receipts;
- atomic status projection with journal reconciliation;
- strict private-key permissions and no model or Melloa dependency.

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) and [`docs/OPERATIONS.md`](docs/OPERATIONS.md). Host-specific workload, firewall, credential-revocation, and owner-authentication wiring remains an owner-reviewed deployment operation; no deployment secret or personal topology belongs here.
