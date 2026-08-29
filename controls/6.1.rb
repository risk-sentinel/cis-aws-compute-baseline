# encoding: UTF-8

control 'C-6.1' do
  title 'Ensure you are using VPC Endpoints for source code access'
  desc  "
    App Runner needs access to your application source, so it can't be encrypted. Therefore, be sure to secure the connection between your development or deployment environment and App Runner.

    Client-side encryption isn't a valid method for protecting the source image or code that you provide to App Runner for deployment. Using a VPC endpoint, you can privately connect your VPC to supported AWS services and VPC endpoint services that are powered by AWS PrivateLink.

    Note that this isn't required if you are deploying your app runner directly from an ECR image as ECR images can be independently encrypted.
  "
  desc  'rationale', "
    App Runner needs access to your application source, so it can't be encrypted. Therefore, be sure to secure the connection between your development or deployment environment and App Runner.

    Client-side encryption isn't a valid method for protecting the source image or code that you provide to App Runner for deployment. Using a VPC endpoint, you can privately connect your VPC to supported AWS services and VPC endpoint services that are powered by AWS PrivateLink.

    Note that this isn't required if you are deploying your app runner directly from an ECR image as ECR images can be independently encrypted.
  "
  desc  'check', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/vpc/`

    2. On the left hand side, click Endpoints.

    3. On the `Endpoints` page.

    4. Review all the endpoints listed under name.

    5. Locate the Endpoint assigned and configured for App Runner.

    6. If there is no Endpoint set for App Runner refer to the remediation below.

    7. Either click the check box, Actions, View Details or click on the VPC endpoint ID.

    8. Confirm these settings
    ```
    1. Service name - `com.amazonaws.\"region\".apprunner`
    Note - \"Region\" will reflect the region that you are operating in.
    2. Status - Available
    3. VPC ID - correctly associated for use with the service
    4. Subnets tab - correctly associated for use with the service
    5. Security Groups tab - correctly associated for use with the service
    6. Policy tab - correctly configured for use with the service
    ```
    9. If the settings listed above are not correct refer to the remediation below.
  "
  desc  'fix', "
    To create an interface endpoint for an App Runner

    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/vpc/`

    2. On the left hand side, click Endpoints.

    3. Click `Create endpoint`.

    4. Under Service category, choose AWS services.

    5. For Service name, select `com.amazonaws.\"region\".apprunner`. \"Region\" will reflect the region that your are operating in.

    6. For VPC, select the VPC from which you'll access App Runner.

    7. For Subnets, select one subnet per Availability Zone.

    8. For Security group, select the security groups to associate with the App Runner endpoint network interfaces.

    9. For Policy, select Custom to attach a VPC endpoint policy that controls the permissions that principals have for performing actions on resources over the VPC endpoint. 

    10. Click `Create endpoint`.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'IA-5 (1) (e)', 'SI-3 a']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-CNA-DFP', 'KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-SVC-SIN']
  tag nist_r4:               ['IA-5 (1) (e)', 'SC-28', 'SI-3 a']
  tag cci:                   ['CCI-001199', 'CCI-000200', 'CCI-002619']
  tag cis_number:            '6.1'
  tag cis_rid:               '6.1'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0601r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('apprunner')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("APPRUNNER out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  inv = aws_apprunner_inventory(regions: compute_scan_regions)
  if inv.connection_error
    describe 'AWS App Runner inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('services_without_vpc_connector') { should be_empty }
    end
  end
end
