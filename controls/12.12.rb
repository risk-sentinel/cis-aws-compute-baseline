# encoding: UTF-8

control 'C-12.12' do
  title 'Ensure encryption in transit is enabled for Lambda environment variables'
  desc  "
    As you can set your own environmental variables for Lambda it is important to also encrypt them for in transit protection.

    Lambda environment variables should be encrypted in transit for client-side protection as they can store sensitive information.
  "
  desc  'rationale', "
    As you can set your own environmental variables for Lambda it is important to also encrypt them for in transit protection.

    Lambda environment variables should be encrypted in transit for client-side protection as they can store sensitive information.
  "
  desc  'check', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/lambda/`.

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review

    4. Click the Configuration tab

    5. In the left column, click `Environment variables`.

    6. In the `Environment variables` section, click `Edit`

    7. On the Edit environment variables page, review the Values.  If they are a long value that resembles this:
    AQICAHhxbKJYcFAU16CbU4IVpzi5CwK
    Encryption is in place for that Key.  If the value is in plain text refer to the remediation below.

    8. Repeat steps 2 - 7 for each Lambda function available within the current AWS region.

    10. Repeat this Audit for all the other AWS regions.

    From the Command line

    1. Run 'aws lambda list-functions'
    ```
    aws lambda list-functions --output table --query \"Functions[*].FunctionName\"
    ```
    This command will provide a table titled `ListFunctions`

    2. Run `aws lambda get-function` 
    ```
    aws lambda get-function --function-name \"name_of_function\" --query \"Configuration.Environment\"
    ```
    This will provide an output of the environment variables created for that function.

    3. Review the Values in the table.  If they contain a long value that resembles this:
    AQICAHhxbKJYcFAU16CbU4IVpzi5CwK.  Encryption is in place for that Key.  If the value is in plain text refer to the remediation below.

    4. Repeat steps 1 - 3 for each Lambda function listed within the current region.

    5. Repeat this Audit for all the other AWS regions.
  "
  desc  'fix', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/lambda/`.

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review

    4. Click the Configuration tab

    5. In the left column, click `Environment variables`.

    6. In the `Environment variables` section, click `Edit`

    7. Click the check box for `Enable helpers for encryption in transit`

    8. Click the `Encrypt` option for all the variable that need to be encrypted.

    8. Repeat steps 2 - 8 for each Lambda function identified in the Audit within the current AWS region.

    10. Repeat this remediation for all the other AWS regions.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'SC-28', 'SI-3 a']
  tag cci:                   ['CCI-002418', 'CCI-001199', 'CCI-002619']
  tag cis_number:            '12.12'
  tag cis_rid:               '12.12'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1212r1_rule'
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

  describe 'Lambda functions with environment variables but no kms_key_arn (env var encryption falls back to the AWS-managed key)' do
    subject { aws_lambda_inventory.functions_missing_env_kms }
    it { should be_empty }
  end
end
