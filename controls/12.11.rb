# encoding: UTF-8

control 'C-12.11' do
  title 'Ensure that the runtime environment versions used for your Lambda functions do not have end of support dates.'
  desc  "
    Always using a recent version of the execution environment configured for your Amazon Lambda functions adheres to best practices for the newest software features, the latest security patches and bug fixes, and performance and reliability.

    When you execute your Lambda functions using recent versions of the implemented runtime environment, you should benefit from new features and enhancements, better security, along with performance and reliability.
  "
  desc  'rationale', "
    Always using a recent version of the execution environment configured for your Amazon Lambda functions adheres to best practices for the newest software features, the latest security patches and bug fixes, and performance and reliability.

    When you execute your Lambda functions using recent versions of the implemented runtime environment, you should benefit from new features and enhancements, better security, along with performance and reliability.
  "
  desc  'check', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/lambda/`.

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review

    4. Click Code tab

    5. In the Runtime settings section, check the Runtime attribute value to determine the runtime version.

    6. Compare the function runtime with the updated list of Amazon Lambda runtimes.  Link is in the resource section

    7. If the version you are using is not the latest or is on the EOL list, the selected Amazon Lambda function is using an old and deprecated runtime environment.

    8. Refer to the remediation below.

    9. Repeat steps 2-6 for each Lambda function within the current region.

    Then repeat the Audit process for all other regions.

    From the Command Line

    1. Run `aws lambda list-functions`
    ```
    aws lambda list-functions --output table --query 'Functions[*].FunctionName'
    ```

    This command will provide a table titled ListFunctions

    2. Run `aws lambda get-function-configuration` using the Function names returned in the table.
    ```
    aws lambda get-function-configuration --function-name \"name_of_fuunction\" --query 'Runtime'
    ```

    3. The command output should return the execution environment

    4. Compare the function runtime with the updated list of Amazon Lambda runtimes.  Link is in the resource section

    7. If the version you are using is not the latest or is on the EOL list, the selected Amazon Lambda function is using an old and deprecated runtime environment.

    8. Refer to the remediation below.
  "
  desc  'fix', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/lambda/`.

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review

    4. Click Code tab

    5. Go to the Runtime settings section.

    6. Click Edit

    7. On the Edit runtime settings page, select the latest supported version of the runtime environment from the dropdown list.
    Note - make sure the correct architecture is also selected.

    8. Click Save

    9. Select the Code tab

    10. Click Test from the Code source section.

    11. Once the testing is completed, the execution result of your Lambda function will be listed

    12. Repeat steps for each Lambda function that failed the Audit within the current region.

    From the Command Line

    1. Run `aws lambda update-function-configuration` using the name of the Function you need to remediate
    ```
    aws lambda update-function-configuration --output table --query 'Functions[*].FunctionName'
    ```

    This command will provide a table titled ListFunctions

    2. Run `aws lambda get-function-configuration` using the Function names returned in the table.
    ```
    aws lambda get-function-configuration --function-name \"name_of_fuunction\" --function-name \"name_of_function\" --runtime \"python3.9\"
    ```

    3. The command output should return the metadata available for the reconfigured function.

    4. Repeat steps 1-2 to upgrade the runtime environment for each Amazon Lambda function found in the Audit.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['MP-6 a', 'SI-2 a']
  tag cci:                   ['CCI-001028', 'CCI-001225']
  tag cis_number:            '12.11'
  tag cis_rid:               '12.11'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1211r1_rule'
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

  # Empty input is a CONFIGURATION FAILURE per the cis-aws-compute
  # pre-publish posture (see C-2.1.1 / C-2.1.3 / C-3.13). CIS 12.11
  # requires the consumer to declare which Lambda runtimes are
  # currently supported; without that allowlist the control has no
  # rule to evaluate against and must not pass silently.
  allowlist = Array(input('lambda_runtime_allowlist'))
  if allowlist.empty?
    describe 'lambda_runtime_allowlist input' do
      it 'must be populated for CIS 12.11 to evaluate' do
        expect(allowlist).not_to be_empty,
          'Set lambda_runtime_allowlist to the current AWS-supported runtimes the organization has approved (e.g., [python3.12, python3.13, nodejs20.x, nodejs22.x, java21, dotnet8]). AWS publishes the supported-runtime list at https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html. Empty input means CIS 12.11 has no rule to evaluate against; flagged as FAIL rather than silently skipping.'
      end
    end
  else
    describe aws_lambda_compliance(regions: input('scan_regions'), runtime_allowlist: allowlist) do
      its('functions_with_eol_runtime') { should be_empty }
    end
  end
end
