# cis-aws-compute — verification coverage matrix

Phase C (verification-rigor sweep). Principle: **verify the technical state
wherever the platform can answer it; never accept a human attestation as proof
of a checkable fact.**

Most automation was already established (the auto-detect pre-release pass + PR
#162, which flipped 8 mis-tagged controls to `implemented`: 63 implemented).

| Control(s) | Disposition | Notes |
|---|---|---|
| 63 controls | `implemented` | Direct EC2/Lambda/ECS/Config/etc. API assertions |
| **C-8.2** Batch confused-deputy | **VERIFY (Phase C, default)** | `aws_batch_confused_deputy` enumerates Batch compute-environment service roles and asserts each trust policy carries `aws:SourceAccount`/`aws:SourceArn`. Attestation is now an explicit **opt-out** (set `c_8_2_attestation_uri`) for scanners lacking `batch:Describe*`/`iam:GetRole`. |
| C-5.1 / C-5.2 / C-5.11 / C-5.12 (Lightsail) | attest (`operational`, justified) | Windows-instance OS patching + console-password rotation are **in-guest OS operations** with no AWS-API signal (Lightsail exposes no patch-state / password-age). Genuinely manual → `saf attest apply`. |

## Residual attestation — why
- **C-5.x Lightsail** — patch compliance and credential rotation happen inside the
  guest OS; the Lightsail control plane exposes neither. No API fact to assert.
  (Built for consumers that do run Lightsail.) Freshness floor retained.

`exec_validated: false` on C-8.2 — the Batch/IAM trust-policy resource is not yet
verified against a live account; validate before relying on a FAIL.
