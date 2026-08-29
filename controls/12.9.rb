# encoding: UTF-8

control 'C-12.9' do
  title 'Ensure there are no Lambda functions with admin privileges within your AWS account'
  desc  "
    Ensure that your Amazon Lambda functions don't have administrative permissions potentially giving the function access to all AWS cloud services and resources.

    In order to promote the Principle of Least Privilege (POLP) and provide your functions the minimal amount of access required to perform their tasks the right IAM execution role associated with the function should be used. Instead of providing administrative permissions you should grant the role the necessary permissions that the function really needs.
  "
  desc  'rationale', "
    Ensure that your Amazon Lambda functions don't have administrative permissions potentially giving the function access to all AWS cloud services and resources.

    In order to promote the Principle of Least Privilege (POLP) and provide your functions the minimal amount of access required to perform their tasks the right IAM execution role associated with the function should be used. Instead of providing administrative permissions you should grant the role the necessary permissions that the function really needs.
  "
  desc  'check', "
    From the Console

    1. Login in to the AWS Console using `https://console.aws.amazon.com/lambda/`

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review

    4. Click the Configuration tab

    5. Click on `Permissions` in the left column.

    6. In the Execution role section, click the `Role name` to access the IAM role details.
    Note this will bring you to the IAM Console.

    7. Select the Permissions tab to view the identity-based policies attached

    8. In the Permissions policies section click on the Policy name.

    9. Select the Permissions tab.
    Note The policy summary should show below in JSON format.

    10. Within the {} JSON policy, identify the \"Action\" element defined for each statement and check the value.

    11. If any of the \"Action\" element values are set to \"*\" and the \"Effect\" element is set to \"Allow\", the role policy provides access to all the supported AWS cloud services and resources.

    12. Repeat this step for each IAM policy attached to the selected execution role.

    If one or more policies allow access to all AWS services and resources, the execution role provides administrative permissions.  Refer to the remediation below.
    Repeat steps for each Lambda function within the current region.

    Then repeat the Audit process for all other regions.
  "
  desc  'fix', "
    From the Console

    1. Login in to the AWS Console using `https://console.aws.amazon.com/lambda/`

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to remediate

    4. Click the Configuration tab

    5. Click on `Permissions` in the left column.

    6. In the Execution role section, click the `Edit`

    7. Edit basic settings configuration page:
    ```
    - associate the function with an existing, compliant IAM role
    - click Use an existing role from the Execution role
    - select the required role from the Existing role dropdown
    - click Save
    ```
    OR
    ```
    - apply a new execution role to your Lambda function
    - click Create a new role from AWS policy templates
    - Provide a name for the new role based on org policy
    - select only the necessary permission set(s) from the Policy templates - optional dropdown list.
    - click Save
    ```

    8. Repeat steps for each Lambda function within the current region that failed the Audit.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '12.9'
  tag cis_rid:               '12.9'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1209r1_rule'
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
    its('functions_with_admin_policy') { should be_empty }
  end
end
