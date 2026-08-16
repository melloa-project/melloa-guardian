# Guardian trust boundary

## Purpose

The Guardian provides the final owner-controlled boundary around the autonomous Melloa plane.

## Required modes

- `normal`
- `no-actions`
- `read-only`
- `offline`
- `stopped`
- `recovery`

## Required properties

1. The Guardian runs under separately managed host authority.
2. The Melloa runtime cannot mutate Guardian code, policy, credentials, units, or deployment state.
3. The Guardian can stop Melloa workloads, remove their egress, revoke their brokered credentials, and preserve data for recovery.
4. The owner has a separately authenticated control path that does not rely on Melloa reasoning or ordinary application authorization.
5. Every transition produces an owner-visible receipt and an append-only audit record where available.
6. Failure defaults to restricting autonomous side effects rather than silently restoring authority.

The exact protocol and implementation should remain small and be versioned against the contracts in the main repository.
