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
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS']
  tag nist_r4:               ['AC-2 c']
  tag cci:                   ['CCI-002113']
  tag cis_number:            '8.2'
  tag cis_rid:               '8.2'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0802r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('batch')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("BATCH out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  # VERIFY-don't-trust (Phase C): Batch service-role confused-deputy posture is
  # API-verifiable — enumerate Batch compute-environment service roles and assert
  # each trust policy carries an aws:SourceAccount / aws:SourceArn condition
  # (aws_batch_confused_deputy). VERIFY is the default; the attestation path is an
  # explicit OPT-OUT (set c_8_2_attestation_uri) for consumers whose scanner role
  # lacks batch:DescribeComputeEnvironments / iam:GetRole.
  uri          = input('c_8_2_attestation_uri', value: '')
  max_age_days = input('c_8_2_attestation_max_age_days', value: 365)

  if uri.to_s.empty?
    describe aws_batch_confused_deputy do
      its('roles_without_source_conditions') { should be_empty }
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-8.2 Batch confused-deputy IAM-review attestation (#{uri})" do
      it 'is reachable (no connection error)' do
        expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}"
      end
      it 'exists' do
        expect(doc.exists?).to eq(true)
      end
      it "is current within #{max_age_days} days" do
        expect(doc.current?).to eq(true)
      end
    end
  end
end
