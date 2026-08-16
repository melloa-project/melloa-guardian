# Guardian M0 operations

## Build and test

```bash
make check
make build
```

## Synthetic initialization drill

Use a disposable directory; never use test keys for a real host.

```bash
root="$(mktemp -d)"
bin/guardianctl init \
  --instance-id test-guardian \
  --status-file "$root/status.json" \
  --audit-file "$root/audit.jsonl" \
  --private-key-file "$root/private.pem" \
  --public-key-file "$root/public.pem" \
  --lock-file "$root/guardian.lock"
```

Transition progressively and provide an auditable reason:

```bash
bin/guardianctl transition --mode offline --reason owner.start_local \
  --status-file "$root/status.json" \
  --audit-file "$root/audit.jsonl" \
  --private-key-file "$root/private.pem" \
  --public-key-file "$root/public.pem" \
  --lock-file "$root/guardian.lock"
```

## Deployment boundary

M0 implements signed modes, deterministic transitions, atomic status projection, journal recovery, and independent key custody. Host-specific systemd, firewall, credential-revocation, owner-authentication, and recovery wiring require an owner-reviewed deployment plan because interface names, service units, network topology, and credential providers are deployment state. They must not be guessed or committed here.
