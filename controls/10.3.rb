# encoding: UTF-8

control 'C-10.3' do
  title 'Ensure access logs are enabled.'
  desc  "
    When you enable load balancing, your AWS Elastic Beanstalk environment is equipped with an Elastic Load Balancing load balancer to distribute traffic among the instances in your environment

    For security reasons it is important to have a record of all the access logs and this is enabled within the Load Balancer assigned to the Elastic Beanstalk environments.
  "
  desc  'rationale', "
    When you enable load balancing, your AWS Elastic Beanstalk environment is equipped with an Elastic Load Balancing load balancer to distribute traffic among the instances in your environment

    For security reasons it is important to have a record of all the access logs and this is enabled within the Load Balancer assigned to the Elastic Beanstalk environments.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using https://console.aws.amazon.com/ec2

    2. On the left hand scroll down to Load Balancing and click on `Load Balancers`

    3. Click on the Load balancer associated with the Elastic Beanstalk Environment
    ```
    Typically they have AWSEB in the name.
    If you utilized Elastic Beanstalk to create the Load balancer the Source Security Group listed in the Description will reference `Elastic Beanstalk`
    ```

    4. Under the `Description` tab scroll down to the `Attributes` section

    5. Confirm `Access logs` is set to Enabled.

    6. If status options reads `Disabled` refer to the remediation below.

    7. Repeat steps 3-8 for each environment within the current region.

    8. Then repeat the Audit process for all other regions.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using https://console.aws.amazon.com/ec2

    2. On the left hand scroll down to Load Balancing and click on `Load Balancers`

    3. Click on the Load balancer associated with the Elastic Beanstalk Environment
    ```
    Typically they have AWSEB in the name.
    If you utilized Elastic Beanstalk to create the Load balancer the Source Security Group listed in the Description will reference `Elastic Beanstalk~
    ```

    4. Under the `Description` tab scroll down to the `Attributes` section

    5. Under Access logs - Disabled click on Configure access logs.

    8. Click the check box next to `Enable access logs`.

    9. enter the se bucket name you have setup for the Elastic Beanstalk access logs.
    Note - if you don't have a s3 bucket already created enter an organization name in accordance with policy and have it identify with Elastic Beanstalk.  Then click the check box next to `Create this location for me`

    10. Click `Save`

    11. Scroll down under the description tab and confirm that the Access logs are set as described above.

    12. Repeat steps 3-11 for each Load balancer created and used with Elastic Beanstalk environment within the current region.

    13. Then repeat the remediation process for all other regions identified in the Audit.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '10.3'
  tag cis_rid:               '10.3'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1003r1_rule'
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
    its('environments_without_access_logs') { should be_empty }
  end
end
