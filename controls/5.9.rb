# encoding: UTF-8

control 'C-5.9' do
  title 'Ensure that your Lightsail buckets are not publicly accessible'
  desc  "
    You can make all objects private, public (read-only) or private while making individual objects public (read-only). By default when creating a bucket the permissions are set to \"All objects are private\".

    When the Bucket access permissions are set to All objects are public (read-only) - All objects in the bucket are readable by anyone on the internet through the URL of the bucket.
  "
  desc  'rationale', "
    You can make all objects private, public (read-only) or private while making individual objects public (read-only). By default when creating a bucket the permissions are set to \"All objects are private\".

    When the Bucket access permissions are set to All objects are public (read-only) - All objects in the bucket are readable by anyone on the internet through the URL of the bucket.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select `Storage`.

    5. All Lightsail buckets are listed here.

    6. Underneath the bucket name and size there are 3 possible statements:
    ```
    All objects are private
    All objects are public (read-Only)
    Individual objects can be public
    ```
    7. If any buckets are set to `All objects are public (read-Only)` and or 'Individual objects can be public' refer to the remediation below.

    From the Command Line:

    1. Run `aws lightsail get-buckets`

    ```
    aws lightsail get-buckets
    ```
    This command will provide a list of Buckets tied to Lightsail.

    2. Review the accessRules, getobject and allowPublicOverrides.
    ```
    \"accessRules\": {
                    \"getObject\": \"private\",
                    \"allowPublicOverrides\": false
    ```
    4. If it reads \"getObject\": \"public\" or \"allowPublicOverrides\": true please make note \"name\" of the bucket also listed in the output.

    5. Then refer to the remediation below.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select `Storage`.

    5. All Lightsail buckets are listed here.

    6. Click on the bucket name that has `All objects are public (read-Only)` listed.

    7. Click on `Permissions`

    8. Click on `Change permissions`

    9. Select `All objects are private`

    10. Click `Save`

    11. Repeat for any other Buckets within Lightsail that are set with `All objects are public (read-Only)` and/or `Individual objects can be made public and read only`

    From the Command Line:

    1. Run `aws lightsail update-bucket`

    ```
    aws lightsail update-bucket --bucket-name --access-rules getObject=\"private\",allowPublicOverrides=false
    ```
    2. The confirmation that the change was made will print out after running that command.

    3. Repeat for any other buckets listed in the audit.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '5.9'
  tag cis_rid:               '5.9'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0509r1_rule'
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
      its('buckets_publicly_accessible') { should be_empty }
    end
  end
end
