# encoding: UTF-8

control 'C-2.1.5' do
  title 'Ensure Images are not Publicly Available'
  desc  "
    EC2 allows you to make an AMI public, sharing it with all AWS accounts.

    Publicly sharing an AMI with all AWS accounts could expose organizational data and configuration information.
  "
  desc  'rationale', "
    EC2 allows you to make an AMI public, sharing it with all AWS accounts.

    Publicly sharing an AMI with all AWS accounts could expose organizational data and configuration information.
  "
  desc  'check', "
    Perform the steps below to determine if any AMIs are shared with all AWS accounts.

    From the Console

    1. Login to the EC2 console at `https://console.aws.amazon.com/ec2/`.

    2. In the left pane, under `Images`, click `AMIs`.

    3. Confirm the `Owned by me` is set.

    4. Select the AMI from the list.

    5. Click on the `Permissions` Tab

    6. If this reads `This image is currently Public`.

    Please refer to the remediation below.
  "
  desc  'fix', "
    Perform the steps below to set an AMIs to Private.

    From the Console

    1. Login to the EC2 console at `https://console.aws.amazon.com/ec2/`.

    2. In the left pane, under `Images`, click `AMIs`.

    3. Confirm the `Owned by me` is set.

    4. Select the AMI from the list.

    5. Click on the `Permissions` Tab

    6. Click on `Edit`

    7. Click on the radio button `Private`

    Add AWS Account Number if you have a need to share with other Internal AWS accounts that your Organization owns.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'SC-28']
  tag cci:                   ['CCI-000011', 'CCI-001199']
  tag cis_number:            '2.1.5'
  tag cis_rid:               '2.1.5'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-020105r1_rule'
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

  describe 'Account-owned AMIs marked public=true' do
    subject { aws_amis(owners: ['self']).where(is_public: true).image_ids }
    it { should be_empty }
  end
end
