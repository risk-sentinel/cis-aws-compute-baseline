# encoding: UTF-8

control 'C-2.10' do
  title 'Ensure unused ENIs are removed'
  desc  "
    Identify and delete any unused Amazon AWS Elastic Network Interfaces in order to adhere to best practices and to avoid reaching the service limit. An AWS Elastic Network Interface (ENI) is pronounced unused when is not attached anymore to an EC2 instance.
  "
  desc  'rationale', "
    Identify and delete any unused Amazon AWS Elastic Network Interfaces in order to adhere to best practices and to avoid reaching the service limit. An AWS Elastic Network Interface (ENI) is pronounced unused when is not attached anymore to an EC2 instance.
  "
  desc  'check', "
    From the Console:

    1. Login to EC2 using `https://console.aws.amazon.com/ec2/`

    2. On the left Click `NETWORK & SECURITY`, click `Network Interfaces`.

    3. Select the ENI that you want to review

    4. Go to the Details tab

    5. Check the value set for the Status attribute

    6. If it says `available`, refer to the remediation below.

    7. Repeat steps 3 - 6 to determine the current status for any other `ENIs` within the current region.

    NOTE Repeat the audit process for all other regions used.

    From the CLI

    1. Run describe-network-interfaces command
    ```
    aws ec2 describe-network-interfaces --region us-east-1 --output json --filters Name=status,Values=available --query \"NetworkInterfaces[*].{ENI:NetworkInterfaceId}\"
    ```
    2. The command output should return an empty list if the default security group is not being used.

    3. If there is a list of ENI IDs then refer to the remediation below.

    4. Repeat steps 1 - 3 to determine the current status for any other `ENIs` within the current region.

    NOTE Repeat the audit process for all other regions used.
  "
  desc  'fix', "
    From the Console:

    1. Login to EC2 using `https://console.aws.amazon.com/ec2/`

    2. On the left Click `NETWORK & SECURITY`, click `Network Interfaces`.

    3. Select the ENI that you want to remove

    4. Click 'Actions', then 'delete'

    5. Click `Delete`

    6. Repeat steps 3 - 5 any other `ENIs` listed in the audit within the current region.

    NOTE Repeat the audit process for all other regions used.

    From the CLI

    1. Run the delete-network-interface command with the ENI names collected above in the audit.
    ```
    aws ec2 delete-network-interface --region us-east-1 --network-interface-id eni-1234abcd
    ```
    2. This will remove the ENI that is not being used.

    3. Repeat steps 1 - 2 for any `ENIs` within the current region.

    NOTE Repeat the audit process for all other regions used.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CP-2 a 1', 'SA-8']
  tag cci:                   ['CCI-000443', 'CCI-000664']
  tag cis_number:            '2.10'
  tag cis_rid:               '2.10'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0210r1_rule'
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

  describe 'ENIs in available (unattached) state' do
    subject { aws_ec2_inventory.enis_unattached }
    it { should be_empty }
  end
end
