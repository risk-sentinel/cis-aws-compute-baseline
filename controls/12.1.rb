# encoding: UTF-8

control 'C-12.1' do
  title 'Ensure AWS Config is Enabled for Lambda and Serverless'
  desc  "
    With AWS Config, you can track configuration changes to the Lambda functions (including deleted functions), runtime environments, tags, handler name, code size, memory allocation, timeout settings, and concurrency settings, along with Lambda IAM execution role, subnet, and security group associations.

    This gives you a holistic view of the Lambda function's lifecycle and enables you to surface that data for potential audit and compliance requirements.
  "
  desc  'rationale', "
    With AWS Config, you can track configuration changes to the Lambda functions (including deleted functions), runtime environments, tags, handler name, code size, memory allocation, timeout settings, and concurrency settings, along with Lambda IAM execution role, subnet, and security group associations.

    This gives you a holistic view of the Lambda function's lifecycle and enables you to surface that data for potential audit and compliance requirements.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Config` under Management & Governance.

    3. This will open up the Config dashboard.

    4. Click `Conformance packs`

    5. Review the list of conformance packs.

    6. If `serverless` is listed or included in the conformance pack you built you meet this recommendation.

    7. If `serverless` is not listed refer to the remediation below

    8. If none, see remediation section below.

    9. Repeat steps 3-7 for all regions used.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Config` under Management & Governance.

    3. This will open up the Config dashboard.

    4. Click `Conformance packs`

    5. Click on `Deploy conformance pack`

    6. Click on `Use sample template`

    7. Click the down arrow under Sample template

    8. Scroll down and click on Operational Best Practices for Serverless

    9. Click Next

    10. Give it a Conformance pack name `Serverless`.

    11. Click Next

    12. Click `Deploy conformance pack`

    13. Click on `Deploy conformance pack`

    14. Click on `Use sample template`

    15. Click the down arrow under Sample template

    16. Scroll down and click on Security Best Practices for Lambda

    17. Click Next

    18. Give it a Conformance pack name `LambaSecurity`.

    19. Click Next

    20. Click `Deploy conformance pack`

    21. Repeat steps 2-20 for all regions used.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag nist_r4:               ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '12.1'
  tag cis_rid:               '12.1'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1201r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('lambda')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("LAMBDA out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  # Automated check: AWS Config recorder must include
  # AWS::Lambda::Function in its recording_group.resource_types (OR
  # be recording all supported resource types globally). Member-
  # account-callable via config:DescribeConfigurationRecorders. The
  # control fails when there is no recorder, when no recorder is
  # capturing the Lambda resource type, or when the call itself
  # fails (e.g., missing IAM permission on the scanner role).
  recorders = []
  begin
    resp = aws_config_client.describe_configuration_recorders
    recorders = Array(resp.configuration_recorders).map do |r|
      {
        name:                       r.name,
        all_supported:              r.recording_group&.all_supported,
        include_global:             r.recording_group&.include_global_resource_types,
        resource_types:             Array(r.recording_group&.resource_types),
      }
    end
  rescue StandardError => e
    describe "AWS Config recorder lookup (config:DescribeConfigurationRecorders)" do
      it "should succeed" do
        raise e
      end
    end
  end

  lambda_recorded = recorders.any? do |r|
    r[:all_supported] || r[:resource_types].include?('AWS::Lambda::Function')
  end

  describe 'AWS Config is recording AWS::Lambda::Function' do
    subject { lambda_recorded }
    it { should be true }
  end
end
