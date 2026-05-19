# encoding: UTF-8

control 'C-12.5' do
  title 'Ensure every Lambda function has its own IAM Role'
  desc  "
    Every Lambda function should have a one to one IAM execution role and the roles should not be shared between functions.

    The Principle of Least Privilege means that any Lambda function should have the minimal amount of access required to perform its tasks.  In order to accomplish this Lambda functions should not share IAM Execution roles.
  "
  desc  'rationale', "
    Every Lambda function should have a one to one IAM execution role and the roles should not be shared between functions.

    The Principle of Least Privilege means that any Lambda function should have the minimal amount of access required to perform its tasks.  In order to accomplish this Lambda functions should not share IAM Execution roles.
  "
  desc  'check', "
    From the Console

    1. Login to the AWS console using `https://console.aws.amazon.com/lambda/`

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review.

    4. Click the `Configuration` tab

    5. Under General configuration on the left column, click `Permissions`.

    6. Under the `Execution role` section, `Role name` not the name listed as this is the IAM is the role that defines the access permissions for the selected function.

    7. Repeat steps 2 - 6 for all the Lambda functions listed within the AWS region.

    8. If any Lambda functions share the same Execution role, refer to the remediation below.

    9. Repeat this Audit for all the AWS Regions.
  "
  desc  'fix', "
    From the Console

    1. Login to the AWS console using `https://console.aws.amazon.com/lambda/`

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to change/update.

    4. Click the `Configuration` tab

    5. Under General configuration on the left column, click `Permissions`.

    6. Under the `Execution role` section, click `Edit`.

    7. Scroll down to `Execution role`

    To use an existing IAM role
    ```
    - Click `Use an existing role`
    - Select the role from the `Existing role` dropdown.
    - The IAM role can't be associated with another Lambda function and must follow the Principle of Least Privilege.
    ```

    To use a new IAM role
    ```
    - Click `Create a new role from AWS policy templates`
    - Provide a unique name based on company policy in the `Role name`
    - Select the policy templates from the `Policy templates` dropdown.
    ``` 
    8. Click `Save`

    9. Repeat steps 2 - 8 for all the Lambda functions listed within the AWS region that do not have a unique IAM Execution Role.

    10. Repeat this remediation process for all the AWS Regions.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AU-4']
  tag cci:                   ['CCI-000213', 'CCI-001848']
  tag cis_number:            '12.5'
  tag cis_rid:               '12.5'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1205r1_rule'
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

  describe 'Lambda functions sharing IAM execution roles' do
    subject { aws_lambda_inventory.role_duplicate_offenders }
    it { should be_empty }
  end

  if input('lambda_require_dlq')
    describe 'Lambda functions missing dead_letter_config.target_arn (lambda_require_dlq=true)' do
      subject { aws_lambda_inventory.functions_missing_dlq }
      it { should be_empty }
    end
  end
end
