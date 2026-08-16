# Melloa Guardian

This repository is the independently controlled safety, restriction, shutdown, and recovery plane for Melloa.

The Guardian is deliberately separate from the main Melloa runtime. It owns host-level emergency modes, workload stop, network isolation, credential revocation, and recovery entry points. Melloa and Melli may observe Guardian status through a narrow protocol, but they must not be able to modify, redeploy, disable, or grant authority to the Guardian.

The authoritative architecture is currently maintained in [`melloa-project/melloa`](https://github.com/melloa-project/melloa), especially ADR-008, the control-plane specification, the security model, and the v0.2 decision record.

## Initial repository state

This repository intentionally begins with only its trust boundary and contribution rules. Implement the Guardian after the main repository has defined and tested the narrow Guardian protocol and fake adapter. Keep deployment credentials and owner recovery material outside the main Melloa repository.
