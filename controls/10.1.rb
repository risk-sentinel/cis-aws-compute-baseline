# encoding: UTF-8

control 'C-10.1' do
  title 'Ensure Managed Platform updates is configured'
  desc  "
    AWS Elastic Beanstalk regularly releases platform updates to provide fixes, software updates, and new features. With managed platform updates, you can configure your environment to automatically upgrade to the latest version of a platform during a scheduled maintenance window.

    Your application remains in service during the update process with no reduction in capacity. Managed updates are available on both single-instance and load-balanced environments. They also ensure you aren't introducing any vulnerabilities by running legacy systems that require updates and patches.
  "
  desc  'rationale', "
    AWS Elastic Beanstalk regularly releases platform updates to provide fixes, software updates, and new features. With managed platform updates, you can configure your environment to automatically upgrade to the latest version of a platform during a scheduled maintenance window.

    Your application remains in service during the update process with no reduction in capacity. Managed updates are available on both single-instance and load-balanced environments. They also ensure you aren't introducing any vulnerabilities by running legacy systems that require updates and patches.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using https://console.aws.amazon.com/elasticbeanstalk

    2. On the left hand side click `Environments`

    3. Click on the `Environment name` that you want to review

    4. Under the `environment_name-env` in the left column click `Configuration`

    5. Scroll down under Configurations

    6. Under category look for `Managed updates`

    7. Confirm `Managed updates: enabled`

    8. If status options reads `Managed updates: disabled` refer to the remediation below.

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

    6. Under category look for `Managed updates`

    7. Click on Edit

    8. On the Managed Platform Updates page
    ```
    Managed updates - click the Enable checkbox
    Weekly update window - set preferred maintenance window
    Update level- set it to Minor and patch
    Instance replacement - click the Enabled checkbox
    ```

    9. Click Apply

    10. Repeat steps 3-8 for each environment within the current region that needs Managed updates set.

    11. Then repeat the remediation process for all other regions identified in the Audit.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['MP-6 a', 'SI-2 a']
  tag nist_r4:               ['MP-6 a', 'SI-2 a']
  tag cci:                   ['CCI-001028', 'CCI-001225']
  tag cis_number:            '10.1'
  tag cis_rid:               '10.1'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1001r1_rule'
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

  describe aws_elastic_beanstalk_environments(regions: input('scan_regions')) do
    its('environments_without_managed_updates') { should be_empty }
  end
end
