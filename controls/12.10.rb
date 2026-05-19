# encoding: UTF-8

control 'C-12.10' do
  title 'Ensure Lambda functions do not allow unknown cross account access via permission policies.'
  desc  "
    Ensure that all your Amazon Lambda functions are configured to allow access only to trusted AWS accounts in order to protect against unauthorized cross-account access.

    Allowing unknown (unauthorized) AWS accounts to invoke your Amazon Lambda functions can lead to data exposure and data loss.  To prevent any unauthorized invocation requests for your Lambda functions, restrict access only to trusted AWS accounts.
  "
  desc  'rationale', "
    Ensure that all your Amazon Lambda functions are configured to allow access only to trusted AWS accounts in order to protect against unauthorized cross-account access.

    Allowing unknown (unauthorized) AWS accounts to invoke your Amazon Lambda functions can lead to data exposure and data loss.  To prevent any unauthorized invocation requests for your Lambda functions, restrict access only to trusted AWS accounts.
  "
  desc  'check', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/lambda/`.

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review

    4. Click the Configuration tab

    5. In the left column, click `Permissions`.

    6. In the `Resource-based policy statements` section, click `View policy document`

    7. Review the Resource-based policy document box.  Find the \"Principal\" element and check the element value (ARN).

    8. Confirm that each AWS account ARN is an approved AWS account.  If one or more of the ARNs is not an AWS account defined within your organization, refer to the remediation below.

    9. Repeat steps no. 2-8 for each Lambda function available within the current AWS region.

    10. Repeat this Audit for all the other AWS regions.

    From the Command Line

    1 Run `aws lambda list-functions`
    ``` 
    aws lambda list-functions --output table --query \"Functions[*].FunctionName\"
    ```

    2 This command will provide a table titled ListFunctions

    3 Run `aws lambda get-policy` on the functions listed 
    ```
    aws lambda get-policy --function-name \"name_of_function\" --output text --query \"Policy\"
    ```

    4. This will provide an output of the policy assigned to that function.

    5. Identify the \"Principal\" element for each function for the ARN.
 
    6.  Confirm that each AWS account ARN is an approved AWS account.  If one or more of the ARNs is not an AWS account defined within your organization, refer to the remediation below.

    7. Repeat steps 2-5 for each Lambda function available.
 
    8. Run the Audit in the other AWS cloud regions
  "
  desc  'fix', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/lambda/`.

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review

    4. Click the Configuration tab

    5. In the left column, click `Permissions`.

    6. In the `Resource-based policy statements` section, select the policy statement that allows the unknown AWS Account cross-account access

    7. Click Edit

    8. On the `Edit permissions` page, replace or remove the AWS Account(s) ARN of the unauthorized principal in the Principal box

    9. Click Save

    10. Repeat steps for each Lambda function that failed the Audit
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '12.10'
  tag cis_rid:               '12.10'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1210r1_rule'
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

  describe aws_lambda_compliance(regions: input('scan_regions')) do
    its('functions_with_cross_account_principals') { should be_empty }
  end
end
