# encoding: UTF-8

control 'C-2.4' do
  title 'Ensure an Organizational EC2 Tag Policy has been Created'
  desc  "
    A tag policy enables you to define tag compliance rules to help you maintain consistency in the tags attached to your organization's resources.

    You can use an EC2 tag policy to enforce your tag strategy across all of your EC2 resources.
  "
  desc  'rationale', "
    A tag policy enables you to define tag compliance rules to help you maintain consistency in the tags attached to your organization's resources.

    You can use an EC2 tag policy to enforce your tag strategy across all of your EC2 resources.
  "
  desc  'check', "
    From the Console:

    1. Login to the AWS Organizations using `https://console.aws.amazon.com/organizations/`

    2. On the left click `Policies`

    3. Click on `Tag policies`

    4. Confirm that a policy name exists with a description

    5. Click on the policy for EC2 Tagging as indicated in the name, description or both.

    6. Click on `Edit policy`

    7. Confirm that `Tag key capitalization compliance` is checked

    8. Confirm that `Prevent non-compliant operations for this tag` is checked.

    9. Confirm that `ec2:image`, `ec2:instance` and `ec2:reserved-instances` are listed.

    If the tag policy does not exist with the settings listed above refer to the remediation below.
  "
  desc  'fix', "
    From the Console:
    You must sign in as an IAM user, assume an IAM role, or sign in as the root user (not recommended) in the organization's management account.

    To create a tag policy

    1. Login to the AWS Organizations using `https://console.aws.amazon.com/organizations/`

    2. Left hand side Click on `Policies`

    3. Under `Support policy types` click on `Tag policies`

    4. Under `Available policies` click on `Create policy`

    5. Enter policy name

    6. Enter policy description (Indicate this is the EC2 tag policy)

    7. For New tag key 1, specify the name of a tag key to add.

    8. For `Tag key capitalization compliance` select the box for Use the capitalization to enable this option mandating a specific capitalization for the tag key 
    using this policy.

    9. For `Resource types to enforce` check the box for `Prevent non-compliant operations for this tag`

    10. Click on `Specify resource types`

    11. Expand EC2

    12. Select ec2:image, ec2:instance, ec2:reserved-instances

    13. Click `Save changes`

    14. Click `Create policy`
  "
  tag severity:              'medium'
  tag nist:                  ['CM-8 a 1', 'SI-4 a 1']
  tag cci:                   ['CCI-000389', 'CCI-002641']
  tag cis_number:            '2.4'
  tag cis_rid:               '2.4'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0204r1_rule'
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

  describe 'EC2 instances missing required tags (any-tag when required_ec2_tags is empty; listed keys otherwise)' do
    subject { aws_ec2_inventory.instances_missing_required_tags(input('required_ec2_tags')) }
    it { should be_empty }
  end
end
