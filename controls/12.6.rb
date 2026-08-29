# encoding: UTF-8

control 'C-12.6' do
  title 'Ensure Lambda functions are not exposed to everyone.'
  desc  "
    A publicly accessible Amazon Lambda function is open to the public and can be reviewed by anyone.  To protect against unauthorized users that are sending requests to invoke these functions they need to be changed so they are not exposed to the public.

    Allowing anyone to invoke and run your Amazon Lambda functions can lead to data exposure, data loss, and unexpected charges on your AWS bill.
  "
  desc  'rationale', "
    A publicly accessible Amazon Lambda function is open to the public and can be reviewed by anyone.  To protect against unauthorized users that are sending requests to invoke these functions they need to be changed so they are not exposed to the public.

    Allowing anyone to invoke and run your Amazon Lambda functions can lead to data exposure, data loss, and unexpected charges on your AWS bill.
  "
  desc  'check', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/lambda/`.

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review

    4. Click the Configuration tab

    5. In the left column, click `Permissions`.

    6. In the `Resource-based policy` section, click `View policy document`

    7. Review the Resource-based policy document box.  Find the \"Principal\" element defined for each policy statement and check the element value. If the element has one of the following values: \"*\" or { \"AWS\": \"*\" }, it means it is set to \"Allow\", and if it does not contain a \"Condition\" clause to filter the access, the selected Amazon Lambda function is set to anonymous access.

    8. If any of the Lambda functions have anonymous access set refer to the remediation below.

    9. Repeat steps 2 - 7 for each Lambda function available within the current AWS region.

    10. Repeat this Audit for all the other AWS regions.

    From the Command line

    1. Run 'aws lambda list-functions'
    ```
    aws lambda list-functions --output table --query \"Functions[*].FunctionName\"
    ```
    This command will provide a table titles ListFunctions

    2. Run `aws lambda get-policy` 
    ```
    aws lambda get-policy --function-name \"name_of_function\" --output text --query \"Policy\"
    ```
    This will provide an output of the policy assigned to that function.

    3. Find the \"Principal\" element defined for that function. If the element has one of the following values: \"*\" or { \"AWS\": \"*\" }, it means it is set to \"Allow\", and if it does not contain a \"Condition\" clause to filter the access, the selected Amazon Lambda function is set to anonymous access.

    4. Make note of the Function name from step 1 and the Statement name from step 2 and refer to the remediation steps below.

    5. Repeat steps 1 - 3 for each Lambda function listed within the current region.

    6. Repeat this Audit for all the other AWS regions.
  "
  desc  'fix', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/lambda/`.

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review

    4. Click the Configuration tab

    5. In the left column, click `Permissions`.

    6. In the `Resource-based policy` section, perform the following actions:

    - Under Policy statements
    - Select the policy statement that allows anonymous access
    - Click Delete to remove the non-compliant statement from the resource-based policy attached
    - Within the Delete statement confirmation box, click Remove
    - Click Add permissions to add a new policy statement that grants permissions to a trusted entity only.
    - On the Add permissions page configure the new policy statement to grant access to another AWS account, IAM user, IAM role, or to another AWS service.
    - Click Save

    7. Repeat steps no. 2 - 6 for each Lambda function that fails the Audit above, within the current region.

    8. Repeat this Audit for all the other AWS regions.

    From the Command line

    1. Run 'aws lambda remove-permission'
    ```
    aws lambda remove-permission --function-name \"name_of_function\" --statement-id \"SID_of_Statement\"
    ```
    This command will remove the access policy that is failing the audit for that function.

    2. Run `aws lambda add-permission` 
    ```
    aws lambda add-permission --function-name \"name_of_function\" --statement-id \"correctaccess\" --principal \"012345678910\" --action lambda:InvokeFunction
    ```
    This adds a new policy to the function.  
    *Note The --principal parameter can be the The ID of the trusted AWS account, another AWS account, IAM user, IAM role, or another AWS service.

    3. The command output should display the new policy created.

    4. Repeat steps 1-2 for each Lambda function from the audit for all regions.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-8 a 1', 'CM-7 a']
  tag cci:                   ['CCI-000389', 'CCI-000381']
  tag cis_number:            '12.6'
  tag cis_rid:               '12.6'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1206r1_rule'
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

  describe 'Lambda functions whose resource-based policy allows public (Principal=*) access' do
    subject { aws_lambda_inventory.public_function_names }
    it { should be_empty }
  end

  if input('lambda_require_vpc_attached')
    describe 'Lambda functions not VPC-attached (lambda_require_vpc_attached=true)' do
      subject { aws_lambda_inventory.functions_not_vpc_attached }
      it { should be_empty }
    end
  end
end
