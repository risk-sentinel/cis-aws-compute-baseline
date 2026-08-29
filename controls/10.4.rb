# encoding: UTF-8

control 'C-10.4' do
  title 'Ensure that HTTPS is enabled on load balancer'
  desc  "
    The simplest way to use HTTPS with an Elastic Beanstalk environment is to assign a server certificate to your environment's load balancer.

    When you configure your load balancer to terminate HTTPS, the connection between the client and the load balancer is secure.
  "
  desc  'rationale', "
    The simplest way to use HTTPS with an Elastic Beanstalk environment is to assign a server certificate to your environment's load balancer.

    When you configure your load balancer to terminate HTTPS, the connection between the client and the load balancer is secure.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using https://console.aws.amazon.com/elasticbeanstalk

    2. On the left hand side click `Environments`

    3. Click on the `Environment name` that you want to review

    4. Under the \"environment_name-env\" in the left column click `Configuration`

    5. Scroll down under Configurations

    6. Under category look for `Load balancer`

    7. Click `Edit`

    8. Under the `Listeners` section

    9. Check the Listeners section for any enabled listeners and make sure the Protocol is set to HTTPS and Enabled.

    10. If the Listener is required for HTTP and is not set to HTTPS refer to the remediation below.

    11. Repeat steps 3-10 for each environment within the current region.

    12. Then repeat the Audit process for all other regions.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using https://console.aws.amazon.com/elasticbeanstalk

    2. On the left hand side click `Environments`

    3. Click on the `Environment name` that you want to review

    4. Under the \"environment_name-env\" in the left column click `Configuration`

    5. Scroll down under Configurations

    6. Under category look for `Load balancer`

    7. Click `Edit`

    8. Under the `Listeners` section

    9. Click `Add listener`
    ```
    Set listener port
    Set Listener protocol to HTTPS
    Set Instance Port
    Sent Instance protocol to HTTPS
    Select your SSL certificate
    ```

    10. Click `Add`

    11. Make sure it is listed as enabled.  If you have other listeners not using HTTPS make sure to turn off enabled

    12. Click `Apply` to save the configuration changes.

    13. Repeat steps 3-12 for each environment within the current region.

    14. Then repeat the remediation for all other regions.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag ksi:                   ['KSI-CNA-MAT', 'KSI-CNA-ULN', 'KSI-SVC-SIN']
  tag nist_r4:               ['SC-8']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '10.4'
  tag cis_rid:               '10.4'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1004r1_rule'
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
    its('environments_without_https') { should be_empty }
  end
end
