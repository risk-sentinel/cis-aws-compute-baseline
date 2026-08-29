# encoding: UTF-8

control 'C-3.6' do
  title 'Ensure secrets are not passed as container environment variables in Amazon ECS task definitions'
  desc  "
    Ensure that sensitive secrets, such as `AWS_ACCESS_KEY_ID`, are not passed as environment variables in Amazon ECS task definitions. Use more secure methods, such as secrets management services like AWS Secrets Manager or AWS Systems Manager Parameter Store, to inject these credentials into containers.

    Note: This recommendation assumes that only the latest active revision of a task definition is in use. If older revisions are in use, apply the audit and remediation procedures to those revisions as needed.

    Passing secrets as environment variables exposes them to potential compromise, as they can be easily accessed by any process running within the container or by unauthorized users. This practice can lead to the unintended leakage of sensitive information.
  "
  desc  'rationale', "
    Ensure that sensitive secrets, such as `AWS_ACCESS_KEY_ID`, are not passed as environment variables in Amazon ECS task definitions. Use more secure methods, such as secrets management services like AWS Secrets Manager or AWS Systems Manager Parameter Store, to inject these credentials into containers.

    Note: This recommendation assumes that only the latest active revision of a task definition is in use. If older revisions are in use, apply the audit and remediation procedures to those revisions as needed.

    Passing secrets as environment variables exposes them to potential compromise, as they can be easily accessed by any process running within the container or by unauthorized users. This practice can lead to the unintended leakage of sensitive information.
  "
  desc  'check', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Task definitions`.
    1. Click the name of a task definition.
    1. Click on the latest active revision of the task definition.
    1. Click `JSON`.
    1. For each element under `containerDefinitions`, ensure that the `environment` parameter does not contain `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `ECS_ENGINE_AUTH_DATA`.
    1. Repeat steps 1-6 for each task definition.

    From Command Line:

    Run the following command to list task definitions:

    ```
    aws ecs list-task-definitions
    ```

    For the latest revision of a task definition, run the following command:

    ```
    aws ecs describe-task-definition --task-definition --query 'taskDefinition.containerDefinitions[*].environment[*].name'
    ```

    Ensure that the command does not contain `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `ECS_ENGINE_AUTH_DATA`.

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
    1. For each element under `containerDefinitions`, in the `environment` parameter, remove any objects with a `name` matching `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `ECS_ENGINE_AUTH_DATA`.
    1. Click `Create`.
    1. Repeat steps 1-8 for each task definition requiring remediation.

    Note: When a task definition is updated, running tasks launched from the previous task definition remain unchanged. Updating a running task requires redeploying it with the new task definition.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-12', 'RA-2 a', 'CM-8 a 1']
  tag nist_r4:               ['CM-8 a 1', 'RA-2 a', 'SI-12']
  tag cci:                   ['CCI-001315', 'CCI-001045', 'CCI-000389']
  tag cis_number:            '3.6'
  tag cis_rid:               '3.6'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0306r1_rule'
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
    td.containers_with_secret_shaped_env.map { |c| "#{td.task_definition_arn}:#{c}" }
  end

  describe 'ECS task definitions with secret-shaped environment variables (key name matching password/secret/token/api_key/access_key/private_key)' do
    subject { offenders }
    it { should be_empty }
  end
end
