# encoding: UTF-8

control 'C-3.14' do
  title 'Ensure \'assignPublicIp\' is set to \'DISABLED\' for Amazon ECS task sets'
  desc  "
    Ensure that `assignPublicIp` is set to `DISABLED` for Amazon ECS task sets, to prevent task sets from being publicly accessible.

    Enabling public IP assignment could expose task sets to unintended or unauthorized access.
  "
  desc  'rationale', "
    Ensure that `assignPublicIp` is set to `DISABLED` for Amazon ECS task sets, to prevent task sets from being publicly accessible.

    Enabling public IP assignment could expose task sets to unintended or unauthorized access.
  "
  desc  'check', "
    From Command Line:

    Run the following command to list clusters:

    ```
    aws ecs list-clusters
    ```

    Run the following command to list services in a cluster:

    ```
    aws ecs list-services --cluster ```

    Run the following command to view the task sets for a service:

    ```
    aws ecs describe-task-sets --cluster --service ```

    For each task set, under `networkConfiguration` > `awsvpcConfiguration`, ensure `assignPublicIp` is set to `DISABLED`.

    Repeat for each cluster and service.
  "
  desc  'fix', "
    From Command Line:

    `assignPublicIp` is fixed when a task set is created and cannot be changed in
    place, so remediation means creating a replacement task set and retiring the
    old one.

    Create the replacement with public IP assignment disabled:

    ```
    aws ecs create-task-set --cluster <cluster> --service <service> --task-definition <task-definition> --network-configuration 'awsvpcConfiguration={subnets=[<subnet-id>],securityGroups=[<sg-id>],assignPublicIp=DISABLED}'
    ```

    Shift traffic to it, then delete the task set that assigned a public IP:

    ```
    aws ecs delete-task-set --cluster <cluster> --service <service> --task-set <task-set-arn>
    ```

    Once the public IP is gone the task reaches AWS service endpoints through the
    VPC rather than the internet gateway, so confirm the subnet has a NAT gateway
    or interface endpoints for ECR, CloudWatch Logs and Secrets Manager before
    shifting traffic, or the new task set will fail to start.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.14'
  tag cis_rid:               '3.14'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0314r1_rule'
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

  describe aws_ecs_task_sets(regions: compute_scan_regions) do
    its('task_sets_with_public_ip') { should be_empty }
  end
end
