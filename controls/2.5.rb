# encoding: UTF-8

control 'C-2.5' do
  title 'Ensure no AWS EC2 Instances are Older than 180 days'
  desc  "
    Identify any running AWS EC2 instances older than 180 days.

    An EC2 instance is not supposed to run indefinitely and having instance older than 180 days can increase the risk of problems and issues.
  "
  desc  'rationale', "
    Identify any running AWS EC2 instances older than 180 days.

    An EC2 instance is not supposed to run indefinitely and having instance older than 180 days can increase the risk of problems and issues.
  "
  desc  'check', "
    From the Console:

    1. Login to EC2 using `https://console.aws.amazon.com/ec2/`

    2. On the left Click `INSTANCES`, click `Instances`.

    3. Select the `EC2 instance`. The Instance State must be 'running'.

    4. Select the `Description` tab.

    5. Check the `Launch time`.

    6. Determine the `instance active age`.

    7. If the selected EC2 instance active age is greater than 180 days, refer to the remediation below.

    8. Repeat steps no. 3 - 7 to verify the launch date for all instances.

    9. Go through the other `AWS regions` and repeat the audit process.

    From the CLI

    1. Run the describe-instances command
    ```
    aws ec2 describe-instances --region us-east-1 --output json --filters \"Name=instance-state-code,Values=16\" --query \"Reservations[*].Instances[*].{Instance:InstanceId}\"
    ```
    2 The output should look like this:
    ```
    [
        [
            {
                \"Instance\": \"i-1234567abcdefghi0\"
            }
        ],
        [
            {
                \"Instance\": \"i-1234567abcdefghi0\"
            }
        ],
        [
            {
                \"Instance\": \"i-1234567abcdefghi0\"
            }
        ],
        [
            {
                \"Instance\": \"i-1234567abcdefghi0\"
            }
        ]
    ]
    ```
    3 Run the describe-instances command for each instance ID listed:
    ```
    aws ec2 describe-instances --region us-east-1 --instance-ids i-1234567abcdefghi0 --query \"Reservations[*].Instances[*].LaunchTime\"
    ```
    4. The command output should return the instance launch date in human readable format:
    ```
     \"2021-06-11T15:04:52+00:00\"
    ``
    5. If the selected instance was launched more than 180 days ago, refer to the remediation below.

    6. Repeat steps 3 and 4 to verify the launch date for all instances listed.

    7. Repeat steps 1 - 6 for the other AWS regions.
  "
  desc  'fix', "
    From the Console:

    1. Login to EC2 using `https://console.aws.amazon.com/ec2/`

    2. On the left Click `INSTANCES`, click `Instances`.

    3. Select the `EC2 instance` identified above in the audit. The Instance State must be 'running'.

    4. Click `Actions`, click `Instance State`, click `Stop`.

    5. Wait for the Instance State to read 'stopped'.

    6. Click 'Actions' click 'Instance State', click 'Start'

    7. Select the Description tab.

    8. Check the Launch time.

    Confirm that the instance active age is now set to today's date and time.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-8 a 1']
  tag nist_r4:               ['CM-8 a 1']
  tag cci:                   ['CCI-000389']
  tag cis_number:            '2.5'
  tag cis_rid:               '2.5'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0205r1_rule'
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

  describe 'EC2 instances older than 180 days' do
    subject { aws_ec2_inventory.instances_older_than(180) }
    it { should be_empty }
  end
end
