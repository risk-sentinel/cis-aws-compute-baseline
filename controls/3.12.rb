# encoding: UTF-8

control 'C-3.12' do
  title 'Ensure Amazon ECS task definitions are tagged'
  desc  "
    Ensure all Amazon ECS task definitions have resource tags to facilitate asset management, tracking, and compliance.

    Note: This recommendation assumes that only the latest active revision of a task definition is in use. If older revisions are in use, apply the audit and remediation procedures to those revisions as needed.

    Consistent tagging supports compliance and helps identify unauthorized or misconfigured resources.
  "
  desc  'rationale', "
    Ensure all Amazon ECS task definitions have resource tags to facilitate asset management, tracking, and compliance.

    Note: This recommendation assumes that only the latest active revision of a task definition is in use. If older revisions are in use, apply the audit and remediation procedures to those revisions as needed.

    Consistent tagging supports compliance and helps identify unauthorized or misconfigured resources.
  "
  desc  'check', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Task definitions`.
    1. Click the name of a task definition.
    1. Click on the latest active revision of the task definition.
    1. Click `Tags`.
    1. Ensure at least one tag is listed that does not begin with `aws:`. Tags prefixed with `aws:` are AWS-managed.
    1. Repeat steps 1-6 for each ECS task definition.

    From Command Line:

    Run the following command to list task definitions:

    ```
    aws ecs list-task-definitions
    ```

    For the latest revision of a task definition, run the following command to view the tags:

    ```
    aws ecs list-tags-for-resource --resource-arn ```

    Ensure that tags are returned that do not begin with `aws:`. Tags prefixed with `aws:` are AWS-managed.

    Repeat for each task definition.
  "
  desc  'fix', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Task definitions`.
    1. Click the name of a task definition.
    1. Click on the latest active revision of the task definition.
    1. Click `Create new revision`.
    1. Click `Create new revision` again.
    1. Expand the `Tags` section. 
    1. Click `Add tag`.
    1. Provide a `Key` and optional `Value` for the tag.
    1. Click `Create`.
    1. Repeat steps 1-10 for each task definition requiring remediation.

    Note: When a task definition is updated, running tasks launched from the previous task definition remain unchanged. Updating a running task requires redeploying it with the new task definition.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-8 a 1']
  tag cci:                   ['CCI-000389']
  tag cis_number:            '3.12'
  tag cis_rid:               '3.12'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0312r1_rule'
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

  required = Array(input('required_ecs_tags'))
  offenders = aws_ecs_inventory.latest_active_task_definition_arns.each_with_object([]) do |arn, acc|
    td = aws_ecs_task_definition_full(task_definition: arn)
    next unless td.exists?
    if required.empty?
      acc << td.task_definition_arn if td.tag_keys.empty?
    else
      missing = required - td.tag_keys
      acc << "#{td.task_definition_arn}:missing=#{missing.join(',')}" unless missing.empty?
    end
  end

  describe 'ECS task definitions missing tags (any-tag when required_ecs_tags is empty; listed keys otherwise)' do
    subject { offenders }
    it { should be_empty }
  end
end
