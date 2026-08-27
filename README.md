# cis-aws-compute-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-aws-compute-baseline)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-aws-compute-baseline)

InSpec / CINC Auditor profile validating AWS compute services against the
**CIS AWS Compute Services Benchmark v1.1.0** — 68 controls across EC2, ECS,
Lambda, Batch, Lightsail and Auto Scaling.

Targets **AWS Commercial** and **AWS GovCloud (non-DoD)**. Per-control partition
applicability is in [`partition_applicability.yml`](partition_applicability.yml)
and encoded as `tag applicable_partitions:`.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/cis-aws-compute-baseline
cd cis-aws-compute-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t aws:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

`--input-file` is **not optional**, and the service-scoping pair is the first
thing to set — see below.

### Credentials

Standard AWS credential resolution. Read-only across the compute surface:

```
ec2:Describe*  autoscaling:Describe*  ecs:List*  ecs:Describe*
lambda:List*   lambda:GetFunction*    lambda:GetPolicy
batch:Describe*  lightsail:Get*       ecr:Describe*
iam:GetRole  iam:ListAttachedRolePolicies  ssm:DescribeInstanceInformation
```

### What a first run looks like

Against a real account running a subset of these services:

**68 controls, 68 results — roughly 17 passed / 10 failed / 41 skipped.**

The large skip count is the profile scoping itself out of services this account
does not run, which is the intended behaviour rather than a gap. If you see far
fewer than 68 results, that is the signal to investigate.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml).

| Group | Inputs |
|---|---|
| **Required** | `aws_partition` |
| **Service scoping** | `excluded_services`, `forced_services`, `scan_regions` |
| **Thresholds** | `stopped_instance_max_age_days`, `lambda_require_dlq`, `lambda_require_vpc_attached` |
| **Allow-lists** | `lambda_runtime_allowlist`, `trusted_image_registries`, `approved_amis`, `approved_ami_naming_pattern`, `lightsail_allowed_ssh_cidrs`, `lightsail_allowed_rdp_cidrs`, `required_ecs_tags`, `required_ec2_tags` |
| **Attestation** | four `*_attestation_reference` strings, the `*_base` URIs, `c_8_2_attestation_uri` |

**Scoping down is the normal first step, not an advanced option.** This profile
covers more compute services than any one consumer runs. It assesses what it
discovers and scopes out what is not deployed — but a consumer who does not run
Lightsail should say so explicitly rather than reading its controls as findings.

**An empty allow-list is a real state.** It means the control has nothing to
check against and reports that, rather than silently passing. `approved_amis`
empty is not "all AMIs are approved".

**The two Lambda toggles default off deliberately.** A dead-letter queue matters
for async invocation and VPC attachment only when the function needs private
reachability — neither is universal, so neither is assumed.

---

## Controls

68 controls across six services:

| Service | Assesses |
|---|---|
| EC2 | IMDSv2, EBS encryption, public IP exposure, stopped-instance age, SSM managed status, tagging |
| ECS | task-definition hardening, privileged mode, logging, tagging |
| Lambda | runtime currency, public invoke policy, environment-variable secrets, DLQ and VPC posture |
| Batch | job-definition privileges and IAM scoping |
| Lightsail | SSH/RDP exposure, snapshot and firewall posture |
| Auto Scaling | launch-template IMDSv2 and encryption inheritance |

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/cis-aws-compute-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-account
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: cis-aws-compute-v1.1.0
      profile_version: "0.1.0"
      inputs_file: inputs/mine.yml
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/cis-aws-compute-baseline
    ref: v0.1.7
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-account
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: cis-aws-compute-v1.1.0
      profile_version: "0.1.0"
      inputs_file: inputs/mine.yml
```

`target`, `boundary`, `aws_region`, `profile_name` and `profile_version` are
required and have no defaults. A missing one is rejected before the job starts —
GitHub refuses the `workflow_call`, GitLab refuses the `include` — rather than
running against the wrong account or filing the results under the wrong label.
`inputs_file` defaults to `inputs/example.yml`, which runs with example values,
so set it to your own copy. See [docs/ci-templates.md](docs/ci-templates.md) for
the full contract, including which secrets are genuinely optional.

An `include:` brings YAML and nothing else, which is why the logic lives in the
YAML rather than in a script an including project would never receive. The
templates are carried in this repository on purpose: clone it or include it and
you have the entire pipeline, with nothing else to install.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump. On 3.5.1, `@1` and `@2` are byte-identical.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.
An audit chain where every field is self-asserted is a story.

Schema authority: the shared evidence-store schema.

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: cis-aws-compute-v1.1.0
    git: https://github.com/risk-sentinel/cis-aws-compute-baseline.git
    tag: v0.1.5
```

Then `include_controls 'cis-aws-compute-v1.1.0'` and supply your own inputs. Input overrides
reach the depended profile's controls, so your values win without editing
anything here.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real target before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
