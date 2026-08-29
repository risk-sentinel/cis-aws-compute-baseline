# encoding: UTF-8

control 'C-2.3' do
  title 'Ensure Tag Policies are Enabled'
  desc  "
    Tag policies help you standardize tags on all tagged resources across your organization.

    You can use tag policies to define tag keys (including how they should be capitalized) and their allowed values.
  "
  desc  'rationale', "
    Tag policies help you standardize tags on all tagged resources across your organization.

    You can use tag policies to define tag keys (including how they should be capitalized) and their allowed values.
  "
  desc  'check', "
    From the Console

    1. Login to AWS Organizations using `https://console.aws.amazon.com/organizations/`

    2. In the left pane click on `Policies`

    3. Confirm `Tag policies` status is `enabled`.

    If `Tag policies` status is disabled refer to the remediation below.

    From the CLI

    1. Run the `list-policies` command
    ```
    aws organizations list-policies --filter TAG_POLICY
    ```
    2. If information displays it means you have a tagging policy in place.

    3. If empty brackets display [] refer to the remediation below.
  "
  desc  'fix', "
    From the Console:
    You must sign in as an IAM user, assume an IAM role, or sign in as the root user (not recommended) in the organization's management account.

    1. Login to AWS Organizations using `https://console.aws.amazon.com/organizations/`

    2. In the Left pane click on `Policies`

    3. Click on `Tag policies`

    4. Click on `Enable Tag Policies`

    5. The page is update with a list of the Available policies and the ability to create one.

    From the Command Line:
    You must use an IAM user, assume an IAM role, or sign in as the root user (not recommended) in the organization's management account.

    1. Run the `enable-policy-type` command
    ```
    aws organizations enable-policy-type --root-id --policy-type TAG_POLICIES
    ```
    The list of PolicyTypes in the output will now include the specified policy type with the Status of ENABLED.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-8 a 1', 'SI-4 a 1']
  tag cci:                   ['CCI-000389', 'CCI-002641']
  tag cis_number:            '2.3'
  tag cis_rid:               '2.3'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0203r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('ec2')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("EC2 out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  # Replaces the Organizations-level attestation with per-resource tag
  # enforcement (the operator-observable equivalent). Org-level Tag
  # Policies aren't queryable from a member-account scanner, but the
  # *outcome* the policy is meant to enforce — every workload resource
  # carries the consumer's required tag keys — IS observable per
  # resource. Per the cis-aws-compute pre-publish posture, empty
  # required_ec2_tags is a CONFIGURATION FAILURE (the consumer must
  # declare which tag keys constitute their policy); resources missing
  # any declared tag key OR carrying no tags at all are flagged.
  required = Array(input('required_ec2_tags')).map(&:to_s)
  if required.empty?
    describe 'required_ec2_tags input' do
      it 'must be populated for CIS 2.3 to evaluate' do
        expect(required).not_to be_empty,
          'Set required_ec2_tags to the tag keys the organizational tag policy mandates (e.g., [Environment, Owner, CostCenter, DataClassification]). Empty input means CIS 2.3 has no tag-policy rule to evaluate against; flagged as FAIL rather than silently skipping.'
      end
    end
  else
    # Vendored aws_ec2_instances FilterTable does not register `state`
    # — use aws_ec2_inventory.instances which exposes every instance
    # field via `to_h`. Filter to running instances in Ruby.
    offenders = aws_ec2_inventory.instances.each_with_object([]) do |inst, acc|
      next unless inst.dig(:state, :name).to_s == "running"
      tags = Array(inst[:tags]).each_with_object({}) { |t, h| h[t[:key].to_s] = t[:value].to_s }
      missing = required.reject { |k| tags.key?(k) }
      acc << "#{inst[:instance_id]}: missing required tag keys #{missing.inspect}" unless missing.empty?
    end

    describe 'EC2 instances missing required tag keys (CIS 2.3 — tag-policy enforcement)' do
      subject { offenders }
      it { should be_empty }
    end
  end
end
