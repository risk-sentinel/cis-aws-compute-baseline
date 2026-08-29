# encoding: UTF-8

control 'C-3.10' do
  title 'Ensure Amazon ECS services are tagged'
  desc  "
    Ensure all Amazon ECS services have resource tags to facilitate asset management, tracking, and compliance.

    Consistent tagging supports compliance and helps identify unauthorized or misconfigured resources.
  "
  desc  'rationale', "
    Ensure all Amazon ECS services have resource tags to facilitate asset management, tracking, and compliance.

    Consistent tagging supports compliance and helps identify unauthorized or misconfigured resources.
  "
  desc  'check', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Clusters`.
    1. Click the name of a cluster.
    1. Under `Services`, click the name of a service.
    1. Click `Tags`.
    1. Ensure at least one tag is listed that does not begin with `aws:`. Tags prefixed with `aws:` are AWS-managed.
    1. Repeat steps 1-6 for each ECS cluster and service.

    From Command Line:

    Run the following command to list clusters:

    ```
    aws ecs list-clusters
    ```

    Run the following command to list services in a cluster:

    ```
    aws ecs list-services --cluster ```

    Run the following command to view the tags for a service:

    ```
    aws ecs list-tags-for-resource --resource-arn ```

    Ensure that tags are returned that do not begin with `aws:`. Tags prefixed with `aws:` are AWS-managed.

    Repeat for each cluster and service.
  "
  desc  'fix', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Clusters`.
    1. Click the name of a cluster.
    1. Under `Services`, click the name of a service.
    1. Click `Tags`.
    1. Click `Manage tags`.
    1. Click `Add tag`.
    1. Provide a `Key` and optional `Value` for the tag.
    1. Click `Save`.
    1. Repeat steps 1-9 for each ECS cluster and service requiring remediation.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-8 a 1']
  tag nist_r4:               ['CM-8 a 1']
  tag cci:                   ['CCI-000389']
  tag cis_number:            '3.10'
  tag cis_rid:               '3.10'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0310r1_rule'
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
  offenders = aws_ecs_inventory.service_keys.each_with_object([]) do |key, acc|
    svc = aws_ecs_service_full(cluster: key[:cluster], service: key[:service])
    next unless svc.exists?
    if required.empty?
      acc << svc.service_arn if svc.tag_keys.empty?
    else
      missing = required - svc.tag_keys
      acc << "#{svc.service_arn}:missing=#{missing.join(',')}" unless missing.empty?
    end
  end

  describe 'ECS services missing tags (any-tag when required_ecs_tags is empty; listed keys otherwise)' do
    subject { offenders }
    it { should be_empty }
  end
end
