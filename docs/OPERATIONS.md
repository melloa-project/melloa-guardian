# Guardian M0 operations

## Build and test

Run these commands from the repository root. The drill below uses Bash, needs no elevated privileges, and writes only to a newly created temporary directory.

```bash
make check
make build
```

`make check` runs formatting, `go vet`, and tests. `make build` writes `bin/guardianctl`. A clean source checkout needs Go 1.24 or newer.

## Public handoff for the disposable Melloa preview

Create the handoff from this repository, under owner control:

```bash
make preview-state
```

The target refuses to overwrite an existing handoff. It builds `guardianctl`, creates temporary
control material, prints the signed `stopped` and `offline` receipts, publishes two public inputs
plus a hidden cleanup marker, and removes the temporary private key, audit journal, and lock before
returning:

```text
state/local-preview/status.json
state/local-preview/public.pem
state/local-preview/.melloa-guardian-preview
```

The command also prints shell-ready `GUARDIAN_STATUS` and `GUARDIAN_PUBLIC_KEY` exports. Only those
public paths are passed to Melloa; no `guardianctl` argument or control material is passed. This
same-user drill does not enforce filesystem isolation.

This handoff is a static protocol fixture, not a live Guardian or proof of host isolation. A real
deployment keeps signing and enforcement authority in a separately protected owner plane.

After stopping the Melloa preview, return here and remove the marked public handoff:

```bash
make preview-state-clean
```

Cleanup refuses symlinks, an invalid marker, malformed public files, or unexpected directory
contents. It never recursively removes an arbitrary path. Final empty-directory removal is still a
pathname operation, so this same-user shell drill is not an isolation boundary against a hostile
process racing under the owner's own UID. The empty ignored `state/` parent may remain after the
handoff directory is removed.

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
