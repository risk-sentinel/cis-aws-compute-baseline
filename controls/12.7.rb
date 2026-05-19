# encoding: UTF-8

control 'C-12.7' do
  title 'Ensure Lambda functions are referencing active execution roles.'
  desc  "
    In order to have the necessary permissions to access the AWS cloud services and resources Amazon Lambda functions should be associated with active(available) execution roles.

    A Lambda function's execution role is an Identity and Access Management (IAM) role that grants the function permission to process and access specific AWS services and resources. When Amazon Lambda functions are not referencing active execution roles, the functions are losing the ability to perform critical operations securely.
  "
  desc  'rationale', "
    In order to have the necessary permissions to access the AWS cloud services and resources Amazon Lambda functions should be associated with active(available) execution roles.

    A Lambda function's execution role is an Identity and Access Management (IAM) role that grants the function permission to process and access specific AWS services and resources. When Amazon Lambda functions are not referencing active execution roles, the functions are losing the ability to perform critical operations securely.
  "
  desc  'check', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/lambda/`.

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review

    4. Click the Configuration tab

    5. In the left column, click `Permissions`.

    6. In the `Resource summary` section, if it reads \"The role with name cannot be found. (Service: LambdaConsole; Status Code: 404; Error Code: NoSuchEntity; Request ID: e3f12a73-2988-4dd5-b2d1-237c800a27f4; Proxy: null) refer to the remediation below.

    7. Repeat steps 2 - 6 for each Lambda function available within the current AWS region.

    8. Repeat this Audit for all the other AWS regions.

    From the Command line

    1. Run `aws lambda list-functions`
    ```
    aws lambda list-functions --output table --query \"Functions[*].FunctionName\"
    ```

    This command will provide a table titled ListFunctions

    2. Run `aws lambda get-function` 
    ```
    aws lambda get-function --function-name \"name_of_function\" --query \"Configuration.Role\"
    ```

    This will provide an output returning the role ARN assigned to that function.

    3. Run `aws lambda get-role`
    ```
    aws iam get-role --role-name \"name_of_role\"
    ```

    This will return the requested configuration information.

    4. The command output should return the requested configuration information: 

    5. If the command output returns a `An error occurred (NoSuchEntity) when calling the GetRole operation` error message instead of the role's configuration, the execution role associated with the selected Lambda function is no longer available.  Refer to the remediation below.

    6. Repeat steps 1-5 for each Lambda function available in the selected AWS region. 

    Perform the Audit process for other regions.
  "
  desc  'fix', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/lambda/`.

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to update.

    4. Click the Configuration tab

    5. In the left column, click `Permissions`.

    6. In the `Execution role` section, click Edit

    7. In the `Edit basic settings` page, perform one of the following actions:
    ```
    - Click Use an existing role if you already a execution role for the selected Lambda function.
    - Select the IAM role from the `Existing role` dropdown list.
    - Click Save.
    ```
    Or
    ```
    - Click To create a custom role, go to the `IAM console`.
    - Click AWS Service
    - Click `Lambda`.
    - Click `Next: Permissions
    - Attach the permission policies needed
    - Click Next: Tags
    - Add tags (optional) based on your Organizational policy
    - Click Next: Review
    - Enter a Role name and a Role description so you can attach the policy to the Lambda function
    - Click `Create role`
    - Refresh the Edit basic settings page
    - Select the new IAM role you just created from the `Existing role` dropdown list.
    - Click Save.
    ```
    8. Repeat steps 2 - 7 to update the execution role for each misconfigured Amazon Lambda function within the current AWS region.

    9. Repeat this Audit for all the other AWS regions.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '12.7'
  tag cis_rid:               '12.7'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1207r1_rule'
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

  describe 'Lambda functions referencing IAM execution roles that no longer exist' do
    subject { aws_lambda_inventory.role_invalid_function_names }
    it { should be_empty }
  end
end
