# encoding: UTF-8

control 'C-12.2' do
  title 'Ensure Cloudwatch Lambda insights is enabled'
  desc  "
    Ensure that Amazon CloudWatch Lambda Insights is enabled for your Amazon Lambda functions for enhanced monitoring.

    Amazon CloudWatch Lambda Insights allows you to monitor, troubleshoot, and optimize your Lambda functions. The service collects system-level metrics and summarizes diagnostic information to help you identify issues with your Lambda functions and resolve them as soon as possible. CloudWatch Lambda Insights collects system-level metrics and emits a single performance log event for every invocation of that Lambda function.
  "
  desc  'rationale', "
    Ensure that Amazon CloudWatch Lambda Insights is enabled for your Amazon Lambda functions for enhanced monitoring.

    Amazon CloudWatch Lambda Insights allows you to monitor, troubleshoot, and optimize your Lambda functions. The service collects system-level metrics and summarizes diagnostic information to help you identify issues with your Lambda functions and resolve them as soon as possible. CloudWatch Lambda Insights collects system-level metrics and emits a single performance log event for every invocation of that Lambda function.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com/lambda/`

    2. Click `Functions`.

    3. Click on the name of the function.

    4. Click on the `Configuration tab`

    5. Click on 'Monitoring and operations tools'.

    6. In the Monitoring and operations tools section check the `Enhanced monitoring`

    7. If set to Not enabled, refer to the remediation below.

    8. Repeat steps 2-7 for each Lambda function within the current region.

    9. Then repeat the Audit process for all other regions.

    From the Command Line

    1. Run `aws lambda list-functions`
    ```
    aws lambda list-functions --output table --query \"Functions[*].FunctionName\"
    ```

    This command will provide a table titled `ListFunction`

    2. Run `aws lambda get-function`
    ```
    aws lambda get-function --function-name \"name_of_function\" --query \"'Configuration.Layers[*].Arn\"

    This command should provide the requested ARN

    3. If the list of ARNs does not contain the CloudWatch Lambda Insights extension ARN, i.e. \"arn:aws:lambda: :12345678910:layer:LambdaInsightsExtension: \", the Enhanced Monitoring feature is not enabled.  Refer to the remediation below.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com/lambda/`

    2. Click `Functions`.

    3. Click on the name of the function.

    4. Click on the `Configuration tab`

    5. Click on 'Monitoring and operations tools'.

    6. In the Monitoring and operations tools section click `Edit` to update the monitoring configuration

    7. In the CloudWatch Lambda Insights section click the `Enhanced monitoring` button to enable
    *Note - When you enable the feature using the AWS Management Console, Amazon Lambda adds the required permissions to your function's execution role.

    8. Click Save

    9. Repeat steps 2-8 for each Lambda function within the current region that fails the Audit.

    10. Then repeat the Audit process for all other regions.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '12.2'
  tag cis_rid:               '12.2'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1202r1_rule'
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

  # Boundary-inheritance path removed per `each_profile_stands_alone`
  # memory — the profile must carry its own technical check rather
  # than punting to a foundations-level boundary attestation. Lambda
  # functions are inspected directly for the CloudWatch Lambda
  # Insights extension layer regardless of the consumer's broader
  # observability stack.
  describe 'Lambda functions missing CloudWatch Lambda Insights extension layer' do
    subject { aws_lambda_inventory.functions_missing_lambda_insights }
    it { should be_empty }
  end
end
