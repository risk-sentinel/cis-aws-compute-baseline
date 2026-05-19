# encoding: UTF-8

control 'C-2.6' do
  title 'Ensure detailed monitoring is enable for production EC2 Instances'
  desc  "
    Ensure that detailed monitoring is enabled for your Amazon EC2 instances.

    Monitoring is an important part of maintaining the reliability, availability, and performance of your Amazon EC2 instances
  "
  desc  'rationale', "
    Ensure that detailed monitoring is enabled for your Amazon EC2 instances.

    Monitoring is an important part of maintaining the reliability, availability, and performance of your Amazon EC2 instances
  "
  desc  'check', "
    From the Console:

    1. Login to EC2 using `https://console.aws.amazon.com/ec2/`

    2. On the left Click `INSTANCES`, click `Instances`.

    3. Select the `EC2 instance` you want to review.

    4. Select the `Description` tab.

    5. Check the `Launch time`.

    6. Determine the level of monitoring by reviewing the 'Monitoring attribute'.

    7. If the value is set to `basic` refer to the remediation below.

    8. Repeat steps no. 3 - 7 to verify the monitoring level for all instances.

    9. Go through the other `AWS regions` and repeat the audit process.

    From the CLI

    1. Run the describe-instances command
    ```
    aws ec2 describe-instances --region us-east-1 --output json --filters \"Name=monitoring-state,Values=disabled\" --query \"Reservations[*].Instances[*].{Instance:InstanceId}\"
    ```
    2. The output should be a list of running instances that have enhanced monitoring disabled.

    3. Based on this list of instance ids refer to the remediation below.
  "
  desc  'fix', "
    From the Console:

    1. Login to EC2 using `https://console.aws.amazon.com/ec2/`

    2. On the left Click `INSTANCES`, click `Instances`.

    3. Select the `EC2 instance` you want to review.

    4. Select the `Monitoring` tab.

    5. Click on 'Enable Detailed Monitoring`

    6. Click on `Yes, Enable`

    8. Repeat steps no. 3 - 6 for any other instances that require detailed monitoring to be enabled.

    From the CLI

    1. Run the monitor-instances command using the list of instances collected in the audit.
    ```
    aws ec2 monitor-instances --instance-ids ```
    2. The output will show 'state: pending'

    3. Wait a few minutes and run the same command again for that instance and it will show enabled.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '2.6'
  tag cis_rid:               '2.6'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0206r1_rule'
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

  describe 'EC2 instances without detailed monitoring (state != enabled)' do
    subject { aws_ec2_inventory.instances_missing_detailed_monitoring }
    it { should be_empty }
  end
end
