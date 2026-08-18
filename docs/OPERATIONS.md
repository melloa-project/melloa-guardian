# Guardian M0 operations

## Build and test

Run these commands from the repository root. The drill below uses Bash, needs no elevated privileges, and writes only to a newly created temporary directory.

```bash
make check
make build
```

`make check` runs formatting, `go vet`, and tests. `make build` writes `bin/guardianctl`. A clean source checkout needs Go 1.24 or newer.

## Synthetic initialization drill

Use a disposable directory; never use test keys for a real host. The Bash array keeps every command pointed at the same isolated files.

```bash
root="$(mktemp -d)"
guardian_flags=(
  --status-file "$root/status.json"
  --audit-file "$root/audit.jsonl"
  --private-key-file "$root/private.pem"
  --public-key-file "$root/public.pem"
  --lock-file "$root/guardian.lock"
)

bin/guardianctl init \
  --instance-id test-guardian \
  --key-id guardian.status-v1 \
  "${guardian_flags[@]}"
```

Transition progressively and provide an auditable reason:

```bash
bin/guardianctl transition \
  --mode offline \
  --reason owner.start_local \
  "${guardian_flags[@]}"
```

Inspect the reconciled signed projection:

```bash
bin/guardianctl status "${guardian_flags[@]}"
```

Expected output includes `mode` `offline`, sequence `2`, and the configured key ID. The append-only `audit.jsonl` is the authoritative transition journal; `status.json` is only the current projection that Melloa reads through its verification adapter.

When finished inspecting the drill, remove the directory named by `$root`. It contains a disposable private key; do not copy or reuse any of its files for an installation.

## Deployment boundary

M0 implements signed modes, deterministic transitions, atomic status projection, journal recovery, and independent key custody. Host-specific systemd, firewall, credential-revocation, owner-authentication, and recovery wiring require an owner-reviewed deployment plan because interface names, service units, network topology, and credential providers are deployment state. They must not be guessed or committed here.
