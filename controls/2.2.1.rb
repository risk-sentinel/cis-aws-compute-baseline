# encoding: UTF-8

control 'C-2.2.1' do
  title 'Ensure EBS volume encryption is enabled'
  desc  "
    Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported.

    Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.
  "
  desc  'rationale', "
    Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported.

    Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.
  "
  desc  'check', "
    From Console:

    1. Login to the EC2 console using https://console.aws.amazon.com/ec2/

    2. Under `Account attributes`, click `EBS encryption`.

    3. Verify `Always encrypt new EBS volumes` displays `Enabled`.

    4. Review every region in-use.

    Note: EBS volume encryption is configured per region.

    From Command Line:

    1. Run 
    ```
    aws --region ec2 get-ebs-encryption-by-default
    ```
    2. Verify that `\"EbsEncryptionByDefault\": true` is displayed.

    3. Review every region in-use.

    Note: EBS volume encryption is configured per region.
  "
  desc  'fix', "
    From Console:

    1. Login to the EC2 console using https://console.aws.amazon.com/ec2/

    2. Under `Account attributes`, click `EBS encryption`.

    3. Click `Manage`.

    4. Click the `Enable` checkbox.

    5. Click `Update EBS encryption`

    6. Repeat for every region requiring the change.

    Note: EBS volume encryption is configured per region.

    From Command Line:

    1. Run 
    ```
    aws --region ec2 enable-ebs-encryption-by-default
    ```
    2. Verify that `\"EbsEncryptionByDefault\": true` is displayed.

    3. Repeat every region requiring the change.

    Note: EBS volume encryption is configured per region.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '2.2.1'
  tag cis_rid:               '2.2.1'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-020201r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('ec2')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("EC2 out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  describe 'EBS volumes with encryption disabled' do
    subject { aws_ebs_volumes_multi_region(regions: input('scan_regions')).where(encrypted: false).volume_ids }
    it { should be_empty }
  end
end
