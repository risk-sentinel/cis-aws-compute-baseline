# encoding: UTF-8

control 'C-3.1' do
  title 'Ensure Amazon ECS task definitions using \'host\' network mode do not allow privileged or root user access to the host'
  desc  "
    Ensure that Amazon ECS task definitions using `host` network mode do not allow privileged or root user access. This protects the host container instance from unauthorized access and privilege escalation.

    Note: This recommendation assumes that only the latest active revision of a task definition is in use. If older revisions are in use, apply the audit and remediation procedures to those revisions as needed.

    Combining host networking mode with privileged or root user access significantly increases the risk of container breakout, where a compromised container can gain control of the host system.
  "
  desc  'rationale', "
    Ensure that Amazon ECS task definitions using `host` network mode do not allow privileged or root user access. This protects the host container instance from unauthorized access and privilege escalation.

    Note: This recommendation assumes that only the latest active revision of a task definition is in use. If older revisions are in use, apply the audit and remediation procedures to those revisions as needed.

    Combining host networking mode with privileged or root user access significantly increases the risk of container breakout, where a compromised container can gain control of the host system.
  "
  desc  'check', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Task definitions`.
    1. Click the name of a task definition.
    1. Click on the latest active revision of the task definition.
    1. If `Network mode` is set to `host`, click `JSON`.
    1. For each element under `containerDefinitions`, ensure that `privileged` is set to `false` or is absent, and ensure that `user` is not set to `root` or is absent.
    1. Repeat steps 1-6 for each task definition.

    From Command Line:

    Run the following command to list task definitions:

    ```
    aws ecs list-task-definitions
    ```

    For the latest revision of a task definition, run the following command:

    ```
    aws ecs describe-task-definition --task-definition ```

    If `networkMode` is set to `host`, ensure that for each element under `containerDefinitions`, `privileged` is set to `false` or is absent, and ensure that `user` is not set to `root` or is absent.

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
    1. For each element under `containerDefinitions`, set `privileged` to `false`, or remove `\"privileged\": true`.
    1. For each element under `containerDefinitions`, set `user` to an appropriate non-root user, or remove `\"user\": \"root\"`.
    1. Click `Create`.
    1. Repeat steps 1-9 for each task definition requiring remediation.

    Note: When a task definition is updated, running tasks launched from the previous task definition remain unchanged. Updating a running task requires redeploying it with the new task definition.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS']
  tag nist_r4:               ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_number:            '3.1'
  tag cis_rid:               '3.1'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0301r1_rule'
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
    next [] unless td.host_network?
    (td.privileged_container_names | td.root_user_container_names).map do |name|
      "#{td.task_definition_arn}:#{name}"
    end
  end

  describe 'ECS task definitions using host network mode with privileged or root containers' do
    subject { offenders }
    it { should be_empty }
  end
end
