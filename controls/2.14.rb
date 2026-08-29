# encoding: UTF-8

control 'C-2.14' do
  title 'Ensure EC2 Auto Scaling Groups Propagate Tags to EC2 Instances that it launches'
  desc  "
    Tags can help with managing, identifying, organizing, searching for, and filtering resources. Additionally, tags can help with security and compliance.  Tags can be propagated from an Auto Scaling group to the EC2 instances that it launches.

    Without tags, EC2 instances created via Auto Scaling can be without tags and could be out of compliance with security policy.
  "
  desc  'rationale', "
    Tags can help with managing, identifying, organizing, searching for, and filtering resources. Additionally, tags can help with security and compliance.  Tags can be propagated from an Auto Scaling group to the EC2 instances that it launches.

    Without tags, EC2 instances created via Auto Scaling can be without tags and could be out of compliance with security policy.
  "
  desc  'check', "
    AWS Console

    1. Login to AWS Console using https://console.aws.amazon.com

    2. Click All services and click EC2 under Compute.

    3. Select Auto Scaling Groups.

    4. For each Auto Scaling Group's Details, ensure that all tags have `Tag new instances` set to `Yes`.

    5. Repeat Steps 1-4 for each AWS Region used.

    AWS CLI

    1. Run `aws autoscaling describe-auto-scaling-groups`.

    2. Ensure `PropogateAtLaunch` is `true` under `Tags` for each Tag for the Auto Scaling Group.

    3. Repeat Steps 1-2 for each AWS Region used.
  "
  desc  'fix', "
    AWS Console

    1. Login to AWS Console using https://console.aws.amazon.com

    2. Click All services and click EC2 under Compute.

    3. Select Auto Scaling Groups.

    4. Click `Edit` for each Auto Scaling Group.

    5. Check the `Tag new instances` Box for the Auto Scaling Group.

    6. Click `Update`.

    7. Repeat Steps 1-6 for each AWS Region used.

    AWS CLI

    1. Run `aws autoscaling create-or-update-tags` for tags that are not set to `PropogateAtLaunch` for each Auto Scaling Group that does not have this property set to true.

    ```
    aws autoscaling create-or-update-tags \\
        --tags ResourceId=example-autoscaling-group,ResourceType=auto-scaling-group,Key=TagKey,Value=TagValue,PropagateAtLaunch=true 
    ```

    2. Repeat Step 1 for each AWS Region used.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-8 a 1', 'SI-4 a 1']
  tag ksi:                   ['KSI-MLA-RVL', 'KSI-PIY-GIV', 'KSI-SVC-EIS']
  tag nist_r4:               ['CM-8 a 1', 'SI-4 a 1']
  tag cci:                   ['CCI-000389', 'CCI-002641']
  tag cis_number:            '2.14'
  tag cis_rid:               '2.14'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0214r1_rule'
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

  offenders = aws_auto_scaling_groups.names.each_with_object([]) do |asg_name, acc|
    asg = aws_auto_scaling_group(asg_name)
    next unless asg.exists?
    bad = Array(asg.tags).reject { |t| t[:propagate_at_launch] == true }
    bad.each { |t| acc << "#{asg_name}:tag=#{t[:key]}" }
  end

  describe 'Auto Scaling Groups with tags not configured to propagate to launched instances' do
    subject { offenders }
    it { should be_empty }
  end
end
