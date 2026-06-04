# encoding: UTF-8

control 'C-3.13' do
  title 'Ensure only trusted images are used with Amazon ECS'
  desc  "
    Ensure that only trusted container images from verified sources or private repositories are used with Amazon ECS to maintain the integrity and security of workloads.

    Note: This recommendation assumes that only the latest active revision of a task definition is in use. If older revisions are in use, apply the audit and remediation procedures to those revisions as needed.

    Using trusted images reduces the risk of vulnerabilities, malware, or unauthorized modifications compromising ECS tasks.
  "
  desc  'rationale', "
    Ensure that only trusted container images from verified sources or private repositories are used with Amazon ECS to maintain the integrity and security of workloads.

    Note: This recommendation assumes that only the latest active revision of a task definition is in use. If older revisions are in use, apply the audit and remediation procedures to those revisions as needed.

    Using trusted images reduces the risk of vulnerabilities, malware, or unauthorized modifications compromising ECS tasks.
  "
  desc  'check', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Task definitions`.
    1. Click the name of a task definition.
    1. Click on the latest active revision of the task definition.
    1. Click `JSON`.
    1. For each element under `containerDefinitions`, ensure that `image` is set to an image trusted by your organization.
    1. Repeat steps 1-6 for each task definition.

    From Command Line:

    Run the following command to list task definitions:

    ```
    aws ecs list-task-definitions
    ```

    For the latest revision of a task definition, run the following command:

    ```
    aws ecs describe-task-definition --task-definition --query 'taskDefinition.containerDefinitions[*].image'
    ```

    Ensure that the command returns only images trusted by your organization.

    Repeat for each task definition.
  "
  desc  'fix', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Task definitions`.
    1. Click the name of a task definition.
    1. Click on the latest active revision of the task definition.
    1. Click `Create new revision`.
    1. Click `Create new revision with JSON`.
    1. For each element under `containerDefinitions`, set `image` to an appropriate image trusted by your organization.
    1. Repeat steps 1-7 for each task definition requiring remediation.

    Note: When a task definition is updated, running tasks launched from the previous task definition remain unchanged. Updating a running task requires redeploying it with the new task definition.
  "
  tag severity:              'medium'
  tag nist:                  ['MA-3 a']
  tag cci:                   ['CCI-000865']
  tag cis_number:            '3.13'
  tag cis_rid:               '3.13'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0313r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('ecs')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("ECS out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  trusted = Array(input('trusted_image_registries'))
  if trusted.empty?
    # Empty input is a CONFIGURATION FAILURE, not an attestation slot.
    # CIS 3.13 requires the consumer to declare which image registries
    # are trusted; without one, the control cannot evaluate compliance
    # and must not pass silently. Populate `trusted_image_registries`
    # with the registry prefixes the organization has vetted (typically
    # the account's ECR registry + any approved upstream like
    # `public.ecr.aws/<org>/`).
    describe 'trusted_image_registries input' do
      it 'must be populated for CIS 3.13 to evaluate' do
        expect(trusted).not_to be_empty,
          'Set trusted_image_registries to a list of registry prefixes (e.g., ["123456789012.dkr.ecr.us-east-1.amazonaws.com/", "public.ecr.aws/myorg/"]). Empty input means CIS 3.13 has no allowlist to evaluate against; flagged as FAIL rather than silently skipping.'
      end
    end
  else
    offenders = aws_ecs_inventory.latest_active_task_definition_arns.flat_map do |arn|
      td = aws_ecs_task_definition_full(task_definition: arn)
      td.untrusted_image_containers(trusted).map { |c| "#{td.task_definition_arn}:#{c}" }
    end

    describe 'ECS task-definition container images outside trusted_image_registries allowlist' do
      subject { offenders }
      it { should be_empty }
    end
  end
end
