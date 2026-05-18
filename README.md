# AWS Compute Services CIS Baseline

InSpec / CINC Auditor profile validating an AWS account against **CIS AWS Compute Services Benchmark v1.1.0**.

## Scope

- **AWS Commercial** (`aws_partition=aws`) — primary target.
- **AWS GovCloud non-DoD** (`aws_partition=aws-us-gov`) — primary target.
- Azure and other cloud providers — out of scope.

Per-control partition applicability lives in `partition_applicability.yml` and is mirrored on each control via `tag applicable_partitions: [...]`. Controls not applicable to the running partition skip (impact 0.0) via `only_if`; they do not fail.

## Running Locally

Prerequisites: Docker. Vendor once to pull the `inspec-aws` resource pack:

```bash
docker pull risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1

docker run --rm -v "$PWD:/src" risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 \
  vendor /src/profiles/cis-aws-compute --overwrite
```

Execute against AWS Commercial:

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-aws-compute \
  --input-file /src/profiles/cis-aws-compute/inputs.yml \
  --reporter cli json:/src/hdf.json
```

For GovCloud, switch the partition input and region:

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION=us-gov-west-1 \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-aws-compute \
  --input aws_partition=aws-us-gov \
  --reporter cli json:/src/hdf.json
```

## Portability

This profile runs unchanged across AWS partitions and across consumers with different compute footprints. Consumers never fork the profile — they set declared inputs in their own `inputs.yml`.

### Inputs

| Input | Default | When to override |
|---|---|---|
| `aws_partition` | `aws` | Set to `aws-us-gov` for GovCloud non-DoD. |
| `excluded_services` | `[]` (none excluded) | Deny-list of compute services to skip. Empty (default) = scan every service auto-detected as in-use. Used to suppress noise from sandbox or decommissioning services. |
| `forced_services` | `[]` (none forced) | Force-include list. Empty (default) = auto-detect alone governs scope. Used for in-progress stand-ups where the consumer is provisioning a service with zero resources at scan time. |
| `required_ec2_tags` | `[]` | **Empty → FAIL** for CIS 2.3 (tag-policy enforcement). Populate with the tag keys the org tag policy mandates (e.g., `[Environment, Owner, CostCenter, DataClassification]`). Also feeds CIS 2.4 (per-instance enforcement). |
| `required_ecs_tags` | `[]` | Optional tag-key allowlist for ECS clusters / services / task definitions (CIS 3.10 / 3.11 / 3.12). Empty = assert any-tag-present; non-empty = assert each listed key present. |
| `approved_amis` | `[]` | **Empty → FAIL** for CIS 2.1.3. Populate with the AMI IDs approved for use in the account. |
| `approved_ami_naming_pattern` | `''` | **Empty → FAIL** for CIS 2.1.1. Populate with a regex that approved AMIs' `name` field must match (e.g., `^myorg-(ubuntu|amzn2|al2023)-\d{4}-\d{2}-\d{2}$`). |
| `trusted_image_registries` | `[]` | **Empty → FAIL** for CIS 3.13 (only trusted images). Populate with registry-URI prefixes the consumer trusts. |
| `lambda_runtime_allowlist` | `[]` | **Empty → FAIL** for CIS 12.11 (Lambda runtime EOL). Populate with currently-supported runtime IDs (e.g., `[python3.12, nodejs20.x, provided.al2023]`). |
| `lambda_require_dlq` | `false` | Stricter-than-CIS toggle. When true, every Lambda function must have `dead_letter_config.target_arn` set. Recommended for async-event Lambda fleets. |
| `lambda_require_vpc_attached` | `false` | Stricter-than-CIS toggle. When true, every Lambda function must be VPC-attached. Recommended for Lambda functions reaching private VPC infrastructure. |

### Service scope — auto-detect with optional overrides

The profile **auto-detects** which compute services the target account uses and only evaluates controls for services that are present. There is no opt-in allowlist (the legacy `applicable_services` input was removed). Override the auto-detect outcome only when needed:

| Override | When to use |
|---|---|
| `excluded_services` | A service is provisioned in the account but intentionally out-of-scope (sandbox, scheduled decommission). |
| `forced_services` | A service is in-progress with zero resources at scan time, and you want the controls to FAIL rather than silently pass-N/A. |

`excluded_services` takes precedence over `forced_services`. Both stack with `aws_partition`.

Section-to-service mapping (for both inputs):

| CIS section | Service | input value |
|---|---|---|
| 2 | EC2 / EBS / AMI / ENI / ASG | `ec2` |
| 3, 11 | ECS / Fargate | `ecs` |
| 5 | Lightsail | `lightsail` |
| 6 | App Runner | `apprunner` |
| 8 | Batch | `batch` |
| 10 | Elastic Beanstalk | `elasticbeanstalk` |
| 12 | Lambda | `lambda` |
| 16 | SimSpace Weaver | `simspaceweaver` |

### Empty-input → FAIL inputs

Several inputs are **configuration-required**: an empty / null value FAILs the corresponding control rather than silently skipping, because empty means "no rule to evaluate against" — a configuration gap, not a passing posture. The README table above marks each one with **Empty → FAIL**. Populate them in your consumer overlay before running the profile.

### Example: typical AWS consumer `inputs.yml`

```yaml
aws_partition: aws
# excluded_services / forced_services left empty — auto-detect handles
# ec2 / ecs / lambda automatically.

required_ec2_tags:
  - Environment
  - Owner
  - CostCenter
  - DataClassification

approved_amis:
  - ami-0abcd1234efgh5678  # myorg-al2023-2026-04-15
approved_ami_naming_pattern: '^myorg-(ubuntu|amzn2|al2023)-\d{4}-\d{2}-\d{2}$'

trusted_image_registries:
  - 123456789012.dkr.ecr.us-east-1.amazonaws.com/
  - public.ecr.aws/lambda/

lambda_runtime_allowlist:
  - python3.12
  - python3.13
  - nodejs20.x
  - nodejs22.x
  - provided.al2023

lambda_require_dlq: true
lambda_require_vpc_attached: true
```

## NIST 800-53 Tagging

Every control carries `tag nist: [...]` resolved at scaffold time from the XCCDF's DISA CCI identifiers via Heimdall's `CciNistMappingData.ts`. Provenance chain:

```
XCCDF <ident system="http://cyber.mil/cci">CCI-XXXXXX</ident>
    ↓ (lookup in heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts)
NIST 800-53 control (e.g. "AC-2 (3)")
    ↓ (emitted by tools/xccdf_to_inspec/scaffold.py)
tag nist: ['AC-2 (3)']
```

The scaffolder fails loudly if any rule has a CCI not in the map.

## Regenerating From XCCDF

```bash
python3 tools/xccdf_to_inspec/scaffold.py \
  --xccdf benchmarks/xccdf/cis_aws_compute_services_benchmark_v110.xml \
  --cci-map /path/to/heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts \
  --output profiles/cis-aws-compute \
  --profile-name cis-aws-compute \
  --profile-title "AWS Compute Services CIS Baseline" \
  --supports-platform aws
```

Use `--only <cis-number>` to regenerate a single control.

## Status

All 68 controls filled (issue #14) and all `planned` controls closed via the v0.1.0 release-prep sweep (#79 Phase B2). Each control carries a `tag implementation_status:` mapped to OSCAL's native vocabulary — see the [Control Classification Guide](../../docs/dev/Control_Classification_Guide.md).

### Coverage distribution

| Type | `implementation_status` | Count | Meaning |
|---|---|---|---|
| **Automated** | `implemented` | 52 | Real describe against vendored or local resource; produces pass/fail against the target account. |
| **Attestation** | `alternative` | 16 | `skip 'Requires manual review and attestation provided for this control'` — policy / IAM-deep / OS-level / in-app controls handled via the SAF CLI attestation workflow. |
| **Pending-resource** | `planned` | 0 | — |

The 18-control jump from 34 → 52 implemented covers: 8 controls via stock-SDK libraries (`aws_ec2_long_stopped_instances`, `aws_ebs_snapshot_public_access`, `aws_ssm_managed_instances`, `aws_ecs_task_sets`, `aws_elastic_beanstalk_environments`) + 10 controls via extension-image libraries (`aws_lightsail_inventory`, `aws_apprunner_inventory`, `aws_simspaceweaver_inventory`). The extension-image libraries need the `aws-sdk-lightsail` / `aws-sdk-apprunner` / `aws-sdk-simspaceweaver` gems baked into the **Risk Sentinel extended cinc-auditor image** ([sparc-iac#229](https://github.com/risk-sentinel/sparc-iac/issues/229)). Stock cinc-auditor produces a clean HDF — gems missing → connection_error → attestation rationale per `docs/dev/Vendored_Resource_Gaps.md` §5.

The 4-control reclassification (12 → 16 attestation) is genuinely-manual-only Lightsail controls: 5.1 (in-app updates), 5.2 (default-credential rotation), 5.11 (Windows OS patches), 5.12 (auto-generated Windows password rotation). These check in-app / OS-level state that the AWS API doesn't surface; consumers attest from their patch / runbook reviews.

### Per-section breakdown

| Section | Service | Controls | Automated | Attestation | Pending-resource | `exec_validated` |
|---|---|---|---|---|---|---|
| 2 | EC2 / EBS / AMI | 21 | 17 | 4 | 0 | false |
| 3 | ECS | 14 | 13 | 1 | 0 | *pending live exec validation* |
| 5 | Lightsail | 12 | 8 | 4 | 0 | false |
| 6 | App Runner | 1 | 1 | 0 | 0 | false |
| 8 | Batch | 2 | 1 | 1 | 0 | false |
| 10 | Elastic Beanstalk | 4 | 4 | 0 | 0 | false |
| 11 | ECS Fargate ephemeral storage | 1 | 1 | 0 | 0 | *pending live exec validation* |
| 12 | Lambda | 12 | 6 | 6 | 0 | *pending live exec validation* |
| 16 | SimSpace Weaver | 1 | 1 | 0 | 0 | false |

### `exec_validated` semantics

A control tagged `tag exec_validated: false` has a syntactically-valid describe body but has **not** been run against live resources. Sections in scope for a given consumer (per auto-detect, modulo `excluded_services` / `forced_services`) will be validated on the first live `cinc-auditor exec`. Sections whose services are absent from the target account stay untested — a consumer who later adds those services is expected to validate before relying on pass/fail output.

### Local library files

Under `libraries/`:

- `_aws_backend_bootstrap.rb` — verbatim copy from cis-aws-foundations / cis-aws-database / cis-postgresql. Ensures `aws_backend` resolves before any sibling local library file parses. See sparc-validate#24 for context.
- `aws_ecs_cluster_full.rb` — `describe_clusters` with `include=[CONFIGURATIONS, SETTINGS, TAGS]`. Exposes `container_insights`, `fargate_ephemeral_storage_kms_key_id`, `tag_keys`. Backs CIS 3.9 / 3.11 / 11.1.
- `aws_ecs_service_full.rb` — `describe_services` with `include=[TAGS]`. Exposes `launch_type`, `platform_version`, `assign_public_ip`, `tag_keys`. Backs CIS 3.2 / 3.8 / 3.10.
- `aws_ecs_task_definition_full.rb` — `describe_task_definition` with `include=[TAGS]` plus offender-list helpers. Backs CIS 3.1 / 3.3 / 3.4 / 3.5 / 3.6 / 3.7 / 3.12 / 3.13.
- `aws_ecs_inventory.rb` — list helpers: `cluster_arns`, `service_keys`, `latest_active_task_definition_arns` (one ARN per family, per CIS intent).
- `aws_lambda_inventory.rb` — paginated `list_functions` plus offender-list helpers backing all 6 automated CIS 12.x controls and the stricter-than-CIS DLQ / VPC sub-describes (controlled by `lambda_require_dlq` / `lambda_require_vpc_attached`).
- `aws_ec2_inventory.rb` — paginated `describe_instances` (running + stopped + pending + stopping; terminated excluded) plus offender helpers backing the 14 automated CIS section 2 controls.

## See also

Top-level `README.md` for overall repo state and the sub-issue tracker for per-profile progress.
