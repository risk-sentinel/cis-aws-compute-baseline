# encoding: UTF-8

control 'C-3.8' do
  title 'Ensure Amazon ECS Fargate services are using the latest Fargate platform version'
  desc  "
    Ensure that Amazon ECS Fargate services use the latest Fargate platform version to benefit from the latest security enhancements, performance improvements, and feature updates.

    Using the latest Fargate platform version ensures services benefit from up-to-date security patches and features.
  "
  desc  'rationale', "
    Ensure that Amazon ECS Fargate services use the latest Fargate platform version to benefit from the latest security enhancements, performance improvements, and feature updates.

    Using the latest Fargate platform version ensures services benefit from up-to-date security patches and features.
  "
  desc  'check', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Clusters`.
    1. Click the name of a cluster.
    1. Under `Services`, from the `Filter launch type` drop-down menu, select `FARGATE`.
    1. Click the name of a service.
    1. Click `Configuration and networking`.
    1. Under `Service configuration`, ensure `Platform version` is set to `1.4.0` or `LATEST` for Linux, or `1.0.0` or `LATEST` for Windows.
    1. Repeat steps 1-7 for each ECS cluster and Fargate service.

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
    aws ecs describe-services --cluster --services --query 'services[*].[platformFamily,platformVersion]' --output table
    ```

    Where `platformFamily` is `Linux`, ensure `platformVersion` is `1.4.0` or `LATEST`. Where `platformFamily` is `Windows`, ensure `platformVersion` is `1.0.0` or `LATEST`.

    Repeat for each cluster and service.
  "
  desc  'fix', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Clusters`.
    1. Click the name of a cluster.
    1. Under `Services`, from the `Filter launch type` drop-down menu, select `FARGATE`.
    1. Click the name of a service.
    1. Click `Update service`.
    1. Expand the `Compute configuration (advanced)` section.
    1. Under `Platform version`, select `LATEST` from the drop-down menu.
    1. Click `Update`.
    1. Repeat steps 1-9 for each ECS cluster and Fargate service requiring remediation.

    From Command Line:

    For each service requiring remediation, run the following command to set `platformVersion` to `LATEST`:

    ```
    aws ecs update-service --cluster --service --platform-version LATEST
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['MA-3 a']
  tag cci:                   ['CCI-000865']
  tag cis_number:            '3.8'
  tag cis_rid:               '3.8'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0308r1_rule'
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
    next unless svc.exists? && svc.fargate?
    acc << "#{svc.service_arn}:#{svc.platform_version}" unless svc.platform_version == 'LATEST'
  end

  describe 'ECS Fargate services not pinned to platform_version LATEST' do
    subject { offenders }
    it { should be_empty }
  end
end
