# encoding: UTF-8

control 'C-2.1.4' do
  title 'Ensure Images (AMI) are not older than 90 days'
  desc  "
    Ensure that your AMIs are not older than 90 days.

    Using up-to-date AMIs will provide many benefits from OS updates and security patches helping to ensure reliability, security and compliance.
  "
  desc  'rationale', "
    Ensure that your AMIs are not older than 90 days.

    Using up-to-date AMIs will provide many benefits from OS updates and security patches helping to ensure reliability, security and compliance.
  "
  desc  'check', "
    Perform the following to determine the age of an AMI.

    From the Console

    1. Login to the EC2 console at https://console.aws.amazon.com/ec2/.

    2. In the left pane, under `Images`, click `AMIs`.

    3. Select the AMI for review.

    4. Under the `Details` tab

    5. Review the `Creation date`.

    If the age of the selected AMI is greater than 90 days, the AMI is considered outdated and it should be updated.

    6. Repeat steps no. 3 - 5 to verify the date of the other approved AMIs available.

    Repeat all steps for the other regions.

    Refer to the remediation procedure below to update the AMI.

    From the Command Line:

    Run the aws ec2 describe-images command
    ```
    aws ec2 describe-images \\
        --region \\
        --image-ids ```
    Look for CreationDate in response.
    If the age of the selected AMI is greater than 90 days, the AMI is considered outdated and it should be updated.
  "
  desc  'fix', "
    Perform these steps if the Creation date is older than 90 days.

    From the Console

    1. Login to the EC2 console at https://console.aws.amazon.com/ec2/.

    2. In the left pane, under `Images`, click `AMIs`.

    3. Select the AMI to be updated.

    4. Click on Launch

    5. Go through the EC2 Instance creation process.

    6. Apply all system, security and application updates that are applicable to the EC2 instance.

    7. Once completed click on `Instance state`, `Stop instance1.

    8. Click on `Actions`, `Image and templates`, `Create image`

    9. Once the image process has complete return to the AMI list but clicking on `Images`, `AMIs`

    10. Select the AMI that is older than 90 days.

    12. Click on `Actions`, `Deregister`

    Repeat these steps for any other AMIs older than 90 days.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['MA-3 a']
  tag cci:                   ['CCI-000865']
  tag cis_number:            '2.1.4'
  tag cis_rid:               '2.1.4'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-020104r1_rule'
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

  require 'time'
  threshold = Time.now - (90 * 86_400)
  stale = aws_amis(owners: ['self']).where { |row|
    row[:creation_date] && Time.parse(row[:creation_date]) < threshold
  }
  describe 'Account-owned AMIs older than 90 days' do
    subject { stale.image_ids }
    it { should be_empty }
  end
end
