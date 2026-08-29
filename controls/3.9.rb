# encoding: UTF-8

control 'C-3.9' do
  title 'Ensure monitoring is enabled for Amazon ECS clusters'
  desc  "
    Enable AWS CloudWatch Container Insights for Amazon ECS clusters to monitor resource usage, performance, and application health through metrics and logs.

    Monitoring ECS clusters with Container Insights improves visibility, supports faster issue detection, and enhances security by identifying anomalies and resource bottlenecks.
  "
  desc  'rationale', "
    Enable AWS CloudWatch Container Insights for Amazon ECS clusters to monitor resource usage, performance, and application health through metrics and logs.

    Monitoring ECS clusters with Container Insights improves visibility, supports faster issue detection, and enhances security by identifying anomalies and resource bottlenecks.
  "
  desc  'check', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Clusters`.
    1. For each cluster listed in the `CloudWatch monitoring` column, ensure that `Container Insights` is displayed.

    From Command Line:

    Run the following command to list clusters:

    ```
    aws ecs list-clusters
    ```

    Run the following command to view the settings for a cluster:

    ```
    aws ecs describe-clusters --clusters --include SETTINGS --query 'clusters[*].settings'
    ```

    Ensure `containerInsights` is set to `enabled` or `enhanced`.
  "
  desc  'fix', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Clusters`.
    1. Click the name of a cluster.
    1. Click `Update cluster`.
    1. Under `Monitoring`, select the radio button next to `Container Insights` or `Container Insights with enhanced observability.
    1. Click `Update`.
    1. Repeat steps 1-6 for each ECS cluster requiring remediation.

    From Command Line:

    For each cluster requiring remediation, run the following command to enable `containerInsights`:

    ```
    aws ecs update-cluster-settings --cluster --settings name=containerInsights,value=enabled
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag nist_r4:               ['AU-3', 'IA-2 (2)']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_number:            '3.9'
  tag cis_rid:               '3.9'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0309r1_rule'
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

  # Boundary-inheritance path removed per `each_profile_stands_alone`
  # memory — every cluster is inspected directly for the
  # containerInsights setting regardless of the consumer's broader
  # observability stack.
  offenders = aws_ecs_inventory.cluster_arns.each_with_object([]) do |arn, acc|
    c = aws_ecs_cluster_full(cluster: arn)
    next unless c.exists?
    acc << "#{c.cluster_arn}:containerInsights=#{c.container_insights || 'unset'}" unless c.container_insights_enabled?
  end

  describe 'ECS clusters without Container Insights enabled' do
    subject { offenders }
    it { should be_empty }
  end
end
