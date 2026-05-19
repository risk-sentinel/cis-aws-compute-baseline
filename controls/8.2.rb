# encoding: UTF-8

control 'C-8.2' do
  title 'Ensure Batch roles are configured for cross-service confused deputy prevention'
  desc  "
    The Cross-service confused deputy problem is a security issue where an entity that doesn't have permission to perform an action can coerce a more-privileged entity to perform the action.

    Cross-service impersonation can result in the confused deputy problem. Cross-service impersonation can occur when one service (the calling service) calls another service (the called service). The calling service can be manipulated to use its permissions to act on another customer's resources in a way it should not otherwise have permission to access.
  "
  desc  'rationale', "
    The Cross-service confused deputy problem is a security issue where an entity that doesn't have permission to perform an action can coerce a more-privileged entity to perform the action.

    Cross-service impersonation can result in the confused deputy problem. Cross-service impersonation can occur when one service (the calling service) calls another service (the called service). The calling service can be manipulated to use its permissions to act on another customer's resources in a way it should not otherwise have permission to access.
  "
  desc  'check', "
    From the Console

    1. Login to the AWS Console using https://console.aws.amazon.com/iam/

    2. On the left hand side under Access management, Click on `Roles`

    3. Search for any roles related to `Batch`

    4. Click on the role and the Assume Role Policy Document and confirm that the AssumeRole Action has a aws:SourceArn key that contains the full ARN of the Batch resource
    ```
    {
      \"Version\": \"2012-10-17\",
      \"Statement\": [
        {
          \"Effect\": \"Allow\",
          \"Principal\": {
            \"Service\": \"batch.amazonaws.com\"
          },
          \"Action\": \"sts:AssumeRole\",
          \"Condition\": {
            \"ArnLike\": {
              \"aws:SourceArn\": [
                \"arn:aws:batch:us-east-1:123456789012:compute-environment/testCE\",
              ]
            }
          }
        }
      ]
    }
    ```

    5. If it is showing an * within the ARN or does not have this condition key specified, then the Batch process has access to all of the resources defined in that environment.
    ```
    \"arn:aws:batch:us-east-1:123456789012:compute-environment/*\",
    ```

    ```
    {
      \"Version\": \"2012-10-17\",
      \"Statement\": [
        {
          \"Effect\": \"Allow\",
          \"Principal\": {
            \"Service\": \"batch.amazonaws.com\"
          },
          \"Action\": \"sts:AssumeRole\"
        }
      ]
    }
    ```

    6. Repeat for any roles assigned to Batch that have AssumeRole

    7. Refer to the remediation below
  "
  desc  'fix', "
    From the Console

    1. Login to the AWS Console using https://console.aws.amazon.com/iam/

    2. On the left hand side under Access management, Click on `Roles`

    3. Search for any roles identified above in the audit.

    4. Click on the role and update the Action AssumeRole, aws:SourceArn to contain the full ARN of the resource
    ```
    \"aws:SourceArn\": [
                \"arn:aws:batch:us-east-1:123456789012:compute-environment/testCE\",
    ```
    5. Repeat for any roles defined in the Audit.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '8.2'
  tag cis_rid:               '8.2'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0802r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('batch')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("BATCH out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  ref = input('batch_iam_attestation_reference').to_s
  rationale = ref.empty? ?
    'Requires manual review and attestation provided for this control (Batch service-role trust-policy inspection for aws:SourceAccount + aws:SourceArn conditions requires resolving every Batch role; operators attest from their IAM review record. Populate batch_iam_attestation_reference input to surface the reference here.)' :
    "Requires manual review and attestation provided for this control (consumer attestation: #{ref})"
  describe 'AWS Batch service-role confused-deputy review' do
    skip rationale
  end
end
