# encoding: UTF-8

control 'C-12.8' do
  title 'Ensure that Code Signing is enabled for Lambda functions.'
  desc  "
    Ensure that all your Amazon Lambda functions are configured to use the Code Signing feature in order to restrict the deployment of unverified code.

    Code Signing, ensures that the function code is signed by an approved (trusted) source, and that it has not been altered since signing, and that the code signature has not expired or been revoked.
  "
  desc  'rationale', "
    Ensure that all your Amazon Lambda functions are configured to use the Code Signing feature in order to restrict the deployment of unverified code.

    Code Signing, ensures that the function code is signed by an approved (trusted) source, and that it has not been altered since signing, and that the code signature has not expired or been revoked.
  "
  desc  'check', "
    From the Console

    1. Login to the AWS console using `https://console.aws.amazon.com/lambda/`

    2. In the left column, under `AWS Lambda`, click `Functions`.

    3. Under `Function name` click on the name of the function that you want to review.

    4. Click the `Configuration` tab

    5. Under General configuration on the left column, click `Code signing`.

    6. Under the `Code signing configuration` section check for any code signing configurations created for the function.

    7. If there are no code signing configurations available or listed is not enabled, refer to the remediation

    8. Repeat steps 2-7 for each Lambda function within the current region.

    9. Then repeat the Audit process for all other regions.

    From the Command Line

    1. Run `aws lambda list-functions`
    ```
    aws lambda list-functions --output table --query \"Functions[*].FunctionName\"
    ```

    This command will provide a table titled ListFunctions

    2. Run `aws lambda get-function-code-signing-config`
    ```
    aws lambda get-function-code-signing-config --function-name \"name_of_function\" --query \"CodeSigningConfigArn\"

    3. The command output should return an array with the requested ARN(s)

    4. If the get-function-code-signing-config command output returns null, there are no code signing configurations for the Lambda function.

    5. Refer to the remediation below.

    6. Repeat step 2-5 for each Lambda function available in the selected AWS region.

    7. Perform the Audit process for all other regions used.
  "
  desc  'fix', "
    From the Console

    1. Login to the AWS console using `https://console.aws.amazon.com/signer`

    2. Click on `Create Signing Profile` if none are set up.  If you already have some created in the left panel click on `Signing Profiles`, `Create Signing Profile`.
    *Note a Signing Profile is a trusted publisher and is analogous to the use of a digital signing certificate to generate signatures for your application code.

    3. On the `Create Signing Profile` setup page provide
    ```
    Profile name
    Specify the Signature Validity period (6 months up to 12 months is recomended)
    ```

    4. Click on `Create Profile`

    5. Go to the Amazon Lambda console https://console.aws.amazon.com/lambda/.

    6. In the left panel, under Additional resources, click on `Code signing configurations`.

    7. Click on `Create configuration`

    8. On the `Create code signing configuration` setup page:
    - Description box - provide a short description to identify this configuration
    - Click inside the `Signing profile version ARN` box and select the Signing Profile created above.
    - For `Signature validation policy`, click the signature validation policy suitable for your Lambda function.
    Note - A signature check can fail if the code is not signed by an allowed Signing Profile, or if the signature has expired or has been revoked. 
    - Click Enforce - blocking the deployment of the code and also issue a warning.
    - Click `Create configuration`

    9. Go to the Amazon Lambda console https://console.aws.amazon.com/lambda/.

    10. Click Functions.

    11. Under Function name click on the name of the function that you want to review

    12. Click the Configuration tab

    13. In the left menu click Code signing.

    14. Click Edit

    15. On the `Edit code signing`, select the code signing configuration created above from the drop down

    16. Click `Save`

    The Lambda function is now configured to use code signing.

    17. Next Upload a signed .zip file or provide an S3 URL of a signed .zip made by a signing job in AWS Signer.

    18. To start a signing job, go to AWS Signer console at https://console.aws.amazon.com/signer.

    19. In the left panel, click on Signing Jobs.

    20. Start a Signing Job to generate a signature for your code package and place the signed code package in the specified destination path.

    21. Start Signing Job setup page:
    ```
    - Select the Signing Profile created in dropdown list.
    - Code asset source location, specify the Amazon S3 location of the code package (.zip file) to be signed. Only S3 buckets available in the current region are displayed and can be used
    - Signature destination path with prefix where the signed code package should be uploaded.
    - Start Job to deploy your new Signing Job
    - Job status reads Succeeded, you can find the signed .zip package in your assigned S3 bucket.
    ```
    22. Publish the signed code package to the selected Lambda function.

    23. Amazon Lambda will perform signature checks to verify that the code has not been altered since signing
    Note - The service verifies if the code is signed by one of the allowed signing profiles available.

    24. Repeat steps for each Lambda function that was captured in the Audit.
  "
  tag severity:              'medium'
  tag nist:                  ['SI-7 a', 'AC-2 f', 'AU-2 a', 'SI-3 b']
  tag cci:                   ['CCI-002704', 'CCI-000011', 'CCI-000123', 'CCI-001240']
  tag cis_number:            '12.8'
  tag cis_rid:               '12.8'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1208r1_rule'
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

  describe 'Lambda functions without a code-signing-config attached' do
    subject { aws_lambda_inventory.functions_without_code_signing }
    it { should be_empty }
  end
end
