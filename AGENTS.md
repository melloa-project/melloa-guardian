# Guardian agent instructions

This is an owner-controlled security repository, not part of the autonomous Melloa plane.

Before changing it, read `README.md`, `docs/TRUST_BOUNDARY.md`, and the accepted Guardian/security ADRs in `melloa-project/melloa`. Preserve these invariants:

- Melloa cannot write, deploy, disable, or reconfigure the Guardian.
- Guardian decisions are deterministic and never depend on model reasoning.
- Guardian credentials and recovery paths are separate from Melloa credentials.
- Emergency actions remain usable when Melloa, its database, its models, or its normal web console are unavailable.
- No secret, recovery key, host inventory, or personal deployment value is committed here.

Do not broaden scope or grant the main runtime authority over this repository without an explicit owner decision and a recorded security review.
