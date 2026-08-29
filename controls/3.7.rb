# encoding: UTF-8

control 'C-3.7' do
  title 'Ensure logging is configured for Amazon ECS task definitions'
  desc  "
    Configure logging for Amazon ECS task definitions to capture detailed application and container activity.

    Note: This recommendation assumes that only the latest active revision of a task definition is in use. If older revisions are in use, apply the audit and remediation procedures to those revisions as needed.

    Logging facilitates effective monitoring, troubleshooting, and incident response, improving security and enabling rapid threat detection.
  "
  desc  'rationale', "
    Configure logging for Amazon ECS task definitions to capture detailed application and container activity.

    Note: This recommendation assumes that only the latest active revision of a task definition is in use. If older revisions are in use, apply the audit and remediation procedures to those revisions as needed.

    Logging facilitates effective monitoring, troubleshooting, and incident response, improving security and enabling rapid threat detection.
  "
  desc  'check', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Task definitions`.
    1. Click the name of a task definition.
    1. Click on the latest active revision of the task definition.
    1. Click `JSON`.
    1. Ensure that at least one element under `containerDefinitions` has a `logConfiguration` property defined, and that the value for `logDriver` is not `null`.
    1. Repeat steps 1-6 for each task definition.

    From Command Line:

    Run the following command to list task definitions:

    ```
    aws ecs list-task-definitions
    ```

    For the latest revision of a task definition, run the following command:

    ```
    aws ecs describe-task-definition --task-definition --query 'taskDefinition.containerDefinitions[*].logConfiguration'
    ```

    Ensure that the command returns at least one `logConfiguration` object, and that the value for `logDriver` is not `null`.

    Repeat for each task definition.
  "
  desc  'fix', "
    From Console

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Task definitions`.
    1. Click the name of a task definition.
    1. Click on the latest active revision of the task definition.
    1. Click `Create new revision`.
    1. Click `Create new revision` again.
    1. For at least one container, under `Logging` > `Log collection`, check the box next to `Use log collection` and further configure the log collection options as needed.
    1. Click Create.
    1. Repeat steps 1-8 for each task definition requiring remediation.

    Note: When a task definition is updated, running tasks launched from the previous task definition remain unchanged. Updating a running task requires redeploying it with the new task definition.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag nist_r4:               ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '3.7'
  tag cis_rid:               '3.7'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0307r1_rule'
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

  offenders = aws_ecs_inventory.latest_active_task_definition_arns.flat_map do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    td.containers_missing_logging.map { |n| "#{td.task_definition_arn}:#{n}" }
  end

  describe 'ECS task definitions with containers missing log_configuration.log_driver' do
    subject { offenders }
    it { should be_empty }
  end
end
