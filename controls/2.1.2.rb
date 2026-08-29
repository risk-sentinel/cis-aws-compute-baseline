# encoding: UTF-8

control 'C-2.1.2' do
  title 'Ensure Amazon Machine Images (AMIs) are encrypted'
  desc  "
    Amazon Machine Images should utilize EBS Encrypted snapshots

    AMIs backed by EBS snapshots should use EBS encryption. Snapshot volumes can be encrypted and attached to an AMI.
  "
  desc  'rationale', "
    Amazon Machine Images should utilize EBS Encrypted snapshots

    AMIs backed by EBS snapshots should use EBS encryption. Snapshot volumes can be encrypted and attached to an AMI.
  "
  desc  'check', "
    Perform the following to determine AMIs are encrypted:

    From the Console:

    1. Login to the IAM console at `https://console.aws.amazon.com/ec2/`.

    2. In the left pane click `Instances`, click `AMIs`.

    3. In the `Details` tab.

    4. Review the 'Block Devices'

    5. Confirm that it ends with `encrypted`.

    If it doesn't end with encrypted, refer to the remediation below.

    From the Command Line:

    1. Run the aws ec2 describe-images command
    ```
    aws ec2 describe-images --region us-east-1 --owner self --filter \"Name=block-device-mapping.encrypted,Values=false\" --query \"Images[*].[ImageId]\"
    ```
    2. If this produces a list of AMI's make note as these are not encrypted, then refer to the remediation below.
  "
  desc  'fix', "
    Perform the following to encrypt AMI EBS Snapshots:

    From the Console:

    1. Login to the EC2 console at `https://console.aws.amazon.com/ec2/`.

    2. In the left pane click on `AMIs`.

    3. Select the AMI that does not comply to the encryption policy.

    4. Click on `Actions`.

    5. Click on `Copy AMI`.
    ```
         Destination region - `Select the region the AMI is in`.

         Name - `Enter the new Name`

         Description - `Enter the new description`

         Encryption - `Select` Encrypt target EBS snapshots
    ```
    6. Click on Copy AMI

    Once the AMI has finished copying.

    7. Select the AMI that does not have encrypted EBS snapshots.

    8. Click on `Actions`.

    9. Click on `Deregister`

    From the Command Line:

    1. Run the aws ec2 copy-image command to copy AMI with encrypted block device
    ```
    aws ec2 copy-image --name --source-image-id --source-region --encrypted    
    ```
    2. Run aws ec2 deregister-image to deregister older AMIs
    ```
    aws ec2 deregister-image --image-id ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag nist_r4:               ['SC-28']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '2.1.2'
  tag cis_rid:               '2.1.2'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-020102r1_rule'
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

  unencrypted = aws_amis(owners: ['self']).where { |row|
    Array(row[:block_device_mappings]).any? { |bdm| bdm[:ebs] && bdm[:ebs][:encrypted] == false }
  }
  describe 'AMIs (account-owned) with at least one unencrypted EBS block-device mapping' do
    subject { unencrypted.image_ids }
    it { should be_empty }
  end
end
