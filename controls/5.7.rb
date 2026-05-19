# encoding: UTF-8

control 'C-5.7' do
  title 'Ensure you are using an IAM policy to manage access to buckets in Lightsail.'
  desc  "
    The following policy grants a user access to manage a specific bucket in the Amazon Lightsail object storage service.

    This policy grants access to buckets through the Lightsail console, the AWS Command Line Interface (AWS CLI), AWS API, and AWS SDKs.
  "
  desc  'rationale', "
    The following policy grants a user access to manage a specific bucket in the Amazon Lightsail object storage service.

    This policy grants access to buckets through the Lightsail console, the AWS Command Line Interface (AWS CLI), AWS API, and AWS SDKs.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `IAM` under Security, Identity, & Compliance.

    3. Click `Policies`

    4. Click in the `Filter policies by property or policy name and press enter`

    5. Type `Lightsail` and press enter

    6. Click on the policy that contains lightsail in the name

    7. Make sure the `Permissions` tab is selected.

    8. Confirm the policy looks like this
    ```
    {
     \"Version\": \"2012-10-17\",
     \"Statement\": [
     {
     \"Sid\": \"LightsailAccess\",
     \"Effect\": \"Allow\",
     \"Action\": \"lightsail:*\",
     \"Resource\": \"*\"
     },
     {
     \"Sid\": \"S3BucketAccess\",
     \"Effect\": \"Allow\",
     \"Action\": \"s3:*\",
     \"Resource\": [
     \"arn:aws:s3::: /*\",
     \"arn:aws:s3::: \"
     ]
     }
     ]
    }
    ```
    9. If this policy is in place move to the next step.  If it is not in any of the policies listed for `lightsail` refer to the remediation below.

    10. Click on the `Policy usage` tab

    11. Confirm that the correct Group and/or User is listed under Permissions.  If there is no one listed here refer to the remediation below.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `IAM` under Security, Identity, & Compliance.

    3. Click `Policies`

    4. Click `Create policy`

    5. Click on the JSON tab

    6. Copy and paste the policy below into the JSON editor replacing the text in there and filling in the Lightsail bucket names.
    You can find the Lightsail bucket name in the Lightsail console, Storage, Under buckets.
    ```
    {
     \"Version\": \"2012-10-17\",
     \"Statement\": [
     {
     \"Sid\": \"LightsailAccess\",
     \"Effect\": \"Allow\",
     \"Action\": \"lightsail:*\",
     \"Resource\": \"*\"
     },
     {
     \"Sid\": \"S3BucketAccess\",
     \"Effect\": \"Allow\",
     \"Action\": \"s3:*\",
     \"Resource\": [
     \"arn:aws:s3::: /*\",
     \"arn:aws:s3::: \"
     ]
     }
     ]
    }
    ```
    7. Click `Next tags`

    8. Add tags based on your companies outlined Tagging policy that should be in place based on the AWS Foundations Benchmark.

    9. Click `Next review`

    10. Click in `Name*` and give it a name that contains \"Lightsail\"

    11. Review the summary.

    12. Click `Create policy`

    13. Click in the `Filter policies by property or policy name and press enter`

    14. Type `Lightsail` and press enter

    15. Click on the Policy name that you just created.

    16. Click on the `Policy usage` tab

    17. Click `Attach`

    18. Add in the Users or Group that should have this permission.

    19. Click `Attach policy`
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '5.7'
  tag cis_rid:               '5.7'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0507r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('lightsail')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("LIGHTSAIL out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  inv = aws_lightsail_inventory(regions: input('scan_regions'))
  if inv.connection_error
    describe 'Amazon Lightsail inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('buckets_with_iam_managed_access') { should be_empty }
    end
  end
end
