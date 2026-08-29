# encoding: UTF-8

control 'C-10.2' do
  title 'Ensure Persistent logs is setup and configured to S3'
  desc  "
    Elastic Beanstalk can be configured to automatically stream logs to the CloudWatch service.

    With CloudWatch Logs, you can monitor and archive your Elastic Beanstalk application, system, and custom log files from Amazon EC2 instances of your environments.
  "
  desc  'rationale', "
    Elastic Beanstalk can be configured to automatically stream logs to the CloudWatch service.

    With CloudWatch Logs, you can monitor and archive your Elastic Beanstalk application, system, and custom log files from Amazon EC2 instances of your environments.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using https://console.aws.amazon.com/elasticbeanstalk

    2. On the left hand side click `Environments`

    3. Click on the `Environment name` that you want to review

    4. Under the `environment_name-env` in the left column click `Configuration`

    5. Scroll down under Configurations

    6. Under category look for `Softwares`

    7. Confirm `Log streaming: enabled`

    8. If status options reads `Log streaming: disabled` refer to the remediation below.

    9. Repeat steps 3-8 for each environment within the current region.

    10. Then repeat the Audit process for all other regions.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using https://console.aws.amazon.com/elasticbeanstalk

    2. On the left hand side click `Environments`

    3. Click on the `Environment name` that you want to update

    4. Under the `environment_name-env` in the left column click `Configuration`

    5. Scroll down under Configurations

    6. Under category look for `Software`

    7. Click on Edit

    8. On the Modify software page
    ```
    Instance log streaming to CloudWatch Logs
    Log streaming - click the Enabled checkbox
    Set the required retention based on Organization requirements
    Lifecycle - Keep logs after terminating environment
    ```

    9. Click Apply

    10. Repeat steps 3-8 for each environment within the current region that needs Managed updates set.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '10.2'
  tag cis_rid:               '10.2'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1002r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('elasticbeanstalk')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("ELASTICBEANSTALK out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  describe aws_elastic_beanstalk_environments(regions: compute_scan_regions) do
    its('environments_without_persistent_logs') { should be_empty }
  end
end
