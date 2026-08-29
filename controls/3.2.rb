# encoding: UTF-8

control 'C-3.2' do
  title 'Ensure \'assignPublicIp\' is set to \'DISABLED\' for Amazon ECS services'
  desc  "
    Ensure that `assignPublicIp` is set to `DISABLED` for Amazon ECS services, to restrict direct exposure of containers to the public internet.

    Enabling public IP assignment could expose container application servers to unintended or unauthorized access.
  "
  desc  'rationale', "
    Ensure that `assignPublicIp` is set to `DISABLED` for Amazon ECS services, to restrict direct exposure of containers to the public internet.

    Enabling public IP assignment could expose container application servers to unintended or unauthorized access.
  "
  desc  'check', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Clusters`.
    1. Click the name of a cluster.
    1. Under `Services`, click the name of a service.
    1. Click `Configuration and networking`.
    1. Under `Network configuration`, ensure `Auto-assign public IP` is set to `Turned off`.
    1. Repeat steps 1-6 for each ECS cluster and service.

    From Command Line:

    Run the following command to list clusters:

    ```
    aws ecs list-clusters
    ```

    Run the following command to list services in a cluster:

    ```
    aws ecs list-services --cluster ```

    Run the following command to view the details of a service:

    ```
    aws ecs describe-services --cluster --services ```

    Under `networkConfiguration` > `awsvpcConfiguration`, ensure `assignPublicIp` is set to `DISABLED`.

    Repeat for each cluster and service.
  "
  desc  'fix', "
    From Command Line:

    For each service requiring remediation, run the following command to set `assignPublicIp` to `DISABLED`:

    ```
    aws ecs update-service --cluster --service --network-configuration '{\"awsvpcConfiguration\":{\"subnets\":[\" \"],\"securityGroups\":[\" \"],\"assignPublicIp\":\"DISABLED\"}}'
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.2'
  tag cis_rid:               '3.2'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0302r1_rule'
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

  offenders = aws_ecs_inventory.service_keys.each_with_object([]) do |key, acc|
    svc = aws_ecs_service_full(cluster: key[:cluster], service: key[:service])
    next unless svc.exists?
    if svc.assign_public_ip && svc.assign_public_ip != 'DISABLED'
      acc << "#{svc.service_arn}:#{svc.assign_public_ip}"
    end
  end

  describe 'ECS services with assignPublicIp != DISABLED' do
    subject { offenders }
    it { should be_empty }
  end
end
