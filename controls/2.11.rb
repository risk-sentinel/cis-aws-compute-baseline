# encoding: UTF-8

control 'C-2.11' do
  title 'Ensure instances stopped for over 90 days are removed'
  desc  "
    Enable this rule to help with the baseline configuration of Amazon Elastic Compute Cloud (Amazon EC2) instances by checking whether Amazon EC2 instances have been stopped for more than the allowed number of days, according to your organization's standards.
  "
  desc  'rationale', "
    Enable this rule to help with the baseline configuration of Amazon Elastic Compute Cloud (Amazon EC2) instances by checking whether Amazon EC2 instances have been stopped for more than the allowed number of days, according to your organization's standards.
  "
  desc  'check', "
    From the Console

    1. Login to the EC2 console at https://console.aws.amazon.com/ec2/.

    2. In the left pane, click `Instances`, click `Instances`.

    3. Select the Instance for review.

    4. Under the `Details` tab

    5. Review the `Launch time`.

    If the `Launch time` of the selected Instance is greater than 90 days, the Instance has been offline and is considered outdated.

    6. Repeat steps no. 3 - 5 to verify the Launch date for the other instances.

    Repeat all steps for the other regions.

    Refer to the remediation procedure below if any of the `Launch times` are over 90 days.
  "
  desc  'fix', "
    From the Console

    1. Login to the EC2 console at https://console.aws.amazon.com/ec2/.

    2. In the left pane, click `Instances`, click `Instances`.

    3. Select the Instance for that hasn't been used for over 90 days.

    4. Under the `Details` tab

    5. Click `Instance state`, click `Terminate instance`.

    6. Click `Terminate`.

    7.Repeat steps no. 3 - 6 the other instances with a launch date equal to or over 90 days.

    Repeat all steps for the other regions.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-8 a 1']
  tag cci:                   ['CCI-000389']
  tag cis_number:            '2.11'
  tag cis_rid:               '2.11'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0211r1_rule'
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

  describe aws_ec2_long_stopped_instances(
    regions:        compute_scan_regions,
    threshold_days: input('stopped_instance_max_age_days'),
  ) do
    its('long_stopped_instances') { should be_empty }
  end
end
