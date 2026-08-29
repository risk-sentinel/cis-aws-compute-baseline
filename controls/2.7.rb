# encoding: UTF-8

control 'C-2.7' do
  title 'Ensure Default EC2 Security groups are not being used.'
  desc  "
    When an EC2 instance is launched a specified custom security group should be assigned to the instance.

    When an EC2 Instance is launched the default security group is automatically assigned. In error a lot of instances are launched in this way, and if the default security group is configured to allow unrestricted access, it will increase the attack footprint allowing the opportunity for malicious activity.
  "
  desc  'rationale', "
    When an EC2 instance is launched a specified custom security group should be assigned to the instance.

    When an EC2 Instance is launched the default security group is automatically assigned. In error a lot of instances are launched in this way, and if the default security group is configured to allow unrestricted access, it will increase the attack footprint allowing the opportunity for malicious activity.
  "
  desc  'check', "
    From the Console:

    1. Login to EC2 using `https://console.aws.amazon.com/ec2/`

    2. On the left Click `INSTANCES`, click `Instances`.

    3. On the EC2 Instances page, click inside the attributes filter box

    4. Click the Security Group Name from the dropdown list

    5. Type `default` for the attribute value. (This filter will detect the EC2 instances currently associated with the default security group)

    6. Refer to the remediation below using list of Ec2 Instance ids captured.

    NOTE Repeat the audit process for all other regions used.

    From the CLI

    1. Run the describe-instances command
    ```
    aws ec2 describe-instances --region us-east-1 --output json --filters \"Name=instance.group-name,Values=default\" --query \"Reservations[*].Instances[*].{Instance:InstanceId}\"
    ```
    2. The command output should return an empty list if the default security group is not being used.

    3. If there is a list of instance IDs then the default security group is currently attached to those EC2 instances.

    4. Refer to the remediation below using list of EC2 Instance ids captured.

    NOTE Repeat the audit process for all other regions used.
  "
  desc  'fix', "
    From the Console:

    1. Login to EC2 using `https://console.aws.amazon.com/ec2/`

    2. On the left Click `Network & Security`, click `Security Groups`.

    3. Select `Security Groups`

    4. Click on the `default Security Group` you want to review.

    4. Click `Actions`, `View details`.

    5. Select the `Inbound rules` tab

    6. Click on `Edit inbound rules`

    7. Click on `Delete` for all the rules listed

    8. Once there are no rules listed click on 'Save rules`

    8. Repeat steps no. 3 - 8 for any other default security groups listed.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.7'
  tag cis_rid:               '2.7'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0207r1_rule'
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

  describe 'EC2 instances using a default VPC security group' do
    subject { aws_ec2_inventory.instances_in_default_security_group }
    it { should be_empty }
  end
end
