# encoding: UTF-8

control 'C-2.12' do
  title 'Ensure EBS volumes attached to an EC2 instance is marked for deletion upon instance termination'
  desc  "
    This rule ensures that Amazon Elastic Block Store volumes that are attached to Amazon Elastic Compute Cloud (Amazon EC2) instances are marked for deletion when an instance is terminated. If an Amazon EBS volume isn't deleted when the instance that it's attached to is terminated, it may violate the concept of least functionality.
  "
  desc  'rationale', "
    This rule ensures that Amazon Elastic Block Store volumes that are attached to Amazon Elastic Compute Cloud (Amazon EC2) instances are marked for deletion when an instance is terminated. If an Amazon EBS volume isn't deleted when the instance that it's attached to is terminated, it may violate the concept of least functionality.
  "
  desc  'check', "
    From the Console:

    1. Login to EC2 using `https://console.aws.amazon.com/ec2/`

    2. On the left Click `INSTANCES`, click `Instances`.

    3. Select the `EC2 instance` you want to review.

    4. Select the `Storage` tab.

    5. Scroll down until you reach the 'Volume ID' and review the setting for 'Delete on termination'

    6. If the value is set to `No` refer to the remediation below.

    7. Repeat steps no. 3 - 6 to verify the setting.

    9. Go through the other `AWS regions` and repeat the audit process for all instances.

    From the CLI

    1. Run the describe-instances command
    ```
    aws ec2 describe-instances --region us-east-1 --output json --filters \"Name=block-device-mapping.delete-on-termination,Values=false\" --query \"Reservations[*].Instances[*].{Instance:InstanceId}\"
    ```
    2. The output should be a list of instances that have not set 'Delete on termination'.

    3. Make note of the list of instance ids and refer to the remediation below.

    4. Repeat steps no. 1 -3 with the other `AWS regions`.
  "
  desc  'fix', "
    From the Console:

    1. At this time the `delete on termination` setting for existing instances can only be changed using AWS CLI.

    From the CLI

    1. Run the modify-instance-attribute command using the list of instances collected in the audit.
    ```
    aws ec2 modify-instance-attribute --instance-id i-123456abcdefghi0 --block-device-mappings \"[{\\\"DeviceName\\\": \\\"/dev/sda\\\",\\\"Ebs\\\":{\\\"DeleteOnTermination\\\":true}}]\"
    ```
    2. Repeat steps no. 1 with the other instances discovered in all `AWS regions`.

    Note - If you get any errors running the modify-instance-attribute command confirm the instance id and the Device Name for that instance is correct.  The above command is referencing the typical default device name.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-8 a 1']
  tag nist_r4:               ['CM-8 a 1']
  tag cci:                   ['CCI-000389']
  tag cis_number:            '2.12'
  tag cis_rid:               '2.12'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0212r1_rule'
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

  describe 'EC2 instances with EBS volumes not marked delete_on_termination=true' do
    subject { aws_ec2_inventory.instances_without_delete_on_term }
    it { should be_empty }
  end
end
