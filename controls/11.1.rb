# encoding: UTF-8

control 'C-11.1' do
  title 'Ensure customer-managed keys are used to encrypt AWS Fargate ephemeral storage data for Amazon ECS'
  desc  "
    Use customer-managed AWS KMS keys to encrypt AWS Fargate ephemeral storage data for on Amazon ECS, ensuring that sensitive data remains protected during task execution.

    Customer-managed KMS keys offer enhanced control over encryption, including key rotation, access policies, and audit trails.
  "
  desc  'rationale', "
    Use customer-managed AWS KMS keys to encrypt AWS Fargate ephemeral storage data for on Amazon ECS, ensuring that sensitive data remains protected during task execution.

    Customer-managed KMS keys offer enhanced control over encryption, including key rotation, access policies, and audit trails.
  "
  desc  'check', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Clusters`.
    1. Click the name of a cluster.
    1. Ensure that `Fargate ephemeral storage` is not set to `-`.
    1. Repeat steps 1-4 for each ECS cluster.

    From Command Line:

    Run the following command to list clusters:

    ```
    aws ecs list-clusters
    ```

    Run the following command to view the Fargate ephemeral storage KMS key ID configured for a cluster:

    ```
    aws ecs describe-clusters --clusters --include CONFIGURATIONS --query 'clusters[*].configuration.managedStorageConfiguration.fargateEphemeralStorageKmsKeyId'
    ```

    Ensure the command returns a customer-managed KMS key ARN.

    Repeat for each cluster.
  "
  desc  'fix', "
    From Console:

    1. Login to the ECS console using https://console.aws.amazon.com/ecs/.
    1. In the left panel, click `Clusters`.
    1. Click the name of a cluster.
    1. Click `Update cluster`.
    1. Expand the `Encryption` section.
    1. Under `Fargate ephemeral storage`, select a customer-managed KMS key. Note: Ensure the KMS key has appropriate Fargate service permissions.
    1. Click `Update`.
    1. Repeat steps 1-7 for each ECS cluster requiring remediation.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '11.1'
  tag cis_rid:               '11.1'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1101r1_rule'
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

  offenders = aws_ecs_inventory.cluster_arns.each_with_object([]) do |arn, acc|
    c = aws_ecs_cluster_full(cluster: arn)
    next unless c.exists?
    acc << c.cluster_arn unless c.fargate_ephemeral_storage_cmk_configured?
  end

  describe 'ECS clusters without a customer-managed KMS key on Fargate ephemeral storage' do
    subject { offenders }
    it { should be_empty }
  end
end
