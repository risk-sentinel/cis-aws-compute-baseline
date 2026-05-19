# encoding: UTF-8

control 'C-2.2.4' do
  title 'Ensure unused EBS volumes are removed'
  desc  "
    Identify any unused Elastic Block Store (EBS) volumes in your AWS account and remove them.

    Any Elastic Block Store volume created in your AWS account contains data, regardless of being used or not. If you have EBS volumes (other than root volumes) that are unattached to an EC2 instance they should be removed to prevent unauthorized access or data leak to any sensitive data on these volumes.
  "
  desc  'rationale', "
    Identify any unused Elastic Block Store (EBS) volumes in your AWS account and remove them.

    Any Elastic Block Store volume created in your AWS account contains data, regardless of being used or not. If you have EBS volumes (other than root volumes) that are unattached to an EC2 instance they should be removed to prevent unauthorized access or data leak to any sensitive data on these volumes.
  "
  desc  'check', "
    From Console:

    1. Login to the EC2 console using `https://console.aws.amazon.com/ec2/`

    2. Under `Elastic Block Store`, click `Volumes`.

    3. Find the `State` column

    4. Sort by `Available`

    5. Any `Volumes` listed as Available can be deleted as that is the indication the volume is not attached to an instance.
    Capture this list of volume names and refer to the remediation below.

    Note: EBS volumes can be in different regions.  Make sure to review all the regions being utilized.

    From Command Line:

    1. Run describe-volumes
    ```
    aws ec2 describe-volumes --filter Name=status,Values=available --query \"Volumes[*].{ID:VolumeId}\"
    ```
    2. This will provide a list of all the volumes not attached to an instance

    Capture this list of volume names and refer to the remediation below.

    Note: EBS volumes can be in different regions.  Make sure to review all the regions being utilized.
  "
  desc  'fix', "
    From Console:

    1. Login to the EC2 console using `https://console.aws.amazon.com/ec2/`

    2. Under `Elastic Block Store`, click `Volumes`.

    3. Find the `State` column

    4. Sort by `Available`

    5. Select the Volume that you want to delete.

    6. Click `Actions`, `Delete volume`, `Yes, Delete`

    Note: EBS volumes can be in different regions.  Make sure to review all the regions being utilized.

    From Command Line:

    Using the list of `available volumes` identified in the Audit above

    1. Run the delete-volume command
    ```
    aws ec2 delete-volume --volume-id ```
    2. This will delete the volume identified.

    Note:  Using this command will not prompt you for confirmation.  It will delete the volume and you will not be able to recover it.
    Please make sure you have the correct volume and that you have created a snapshot if it is something that needs to be archived.

    Note: EBS volumes can be in different regions.  Make sure to review all the regions being utilized.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-8 a 1']
  tag cci:                   ['CCI-000389']
  tag cis_number:            '2.2.4'
  tag cis_rid:               '2.2.4'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-020204r1_rule'
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

  describe 'EBS volumes in available (unattached) state' do
    subject { aws_ebs_volumes.where(state: 'available').volume_ids }
    it { should be_empty }
  end
end
