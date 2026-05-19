# encoding: UTF-8

control 'C-5.8' do
  title 'Ensure Lightsail instances are attached to the buckets'
  desc  "
    Attaching an Amazon Lightsail instance to a Lightsail storage bucket gives it full programmatic access to the bucket and its objects.

    When you attach instances to buckets, you don't have to manage credentials like access keys. Resource access is ideal if you're configuring software or a plugin on your instance to upload files directly to your bucket. For example, if you want to configure a WordPress instance to store media files on a bucket configuration with bucket storage resource access allows for that securely.
  "
  desc  'rationale', "
    Attaching an Amazon Lightsail instance to a Lightsail storage bucket gives it full programmatic access to the bucket and its objects.

    When you attach instances to buckets, you don't have to manage credentials like access keys. Resource access is ideal if you're configuring software or a plugin on your instance to upload files directly to your bucket. For example, if you want to configure a WordPress instance to store media files on a bucket configuration with bucket storage resource access allows for that securely.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select `Storage`.

    5. All Lightsail buckets are listed here.

    6. Click on a bucket name

    7. Click `Permissions`.

    8. Scroll down to `Resource access` and confirm that your instance is attached.

    9. If the instance using this Storage bucket is not attached refer to the remediation below.

    From the Command Line:

    1. Run `aws lightsail get-buckets`
    ```
    aws lightsail get-buckets
    ```
    This command will provide a list of Buckets tied to Lightsail.

    2. If there are no buckets listed then refer to the remediation below.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Confirm that the `instance` you want to connect to the Storage bucket is in a `running` state

    5. If it is move on to Step 6.  If it is not click on the instance name, then click on `Start`.  Wait for the status to read ` Running`

    6. Select `Storage`.

    7. All Lightsail buckets are listed here.

    8. Click on the bucket you want to associate with the instances.

    9. Click `Permissions`.

    10. Scroll down to `Resource access`.

    11. Click on `Attach instance`

    12. Click on `Choose an instance`

    13. Select the instance

    14. Click Attach

    15. Repeat this for any other instances and buckets that need to be attached.

    From the Command Line:

    1. Run `aws lightsail create-bucket`
    ```
    aws lightsail create-bucket --bucket-name test-cli-bucket2 --bundle-id small_1_0
    ```
    This command will create a bucket.

    If you want to review the bundle size ids run this command.
    ```
    aws lightsail get-bucket-bundles
    ```
    ```
    \"bundles\": [
            {
                \"bundleId\": \"small_1_0\",
                \"name\": \"Object Storage 5GB\",
                \"price\": 1.0,
                \"storagePerMonthInGb\": 5,
                \"transferPerMonthInGb\": 25,
                \"isActive\": true
            },
            {
                \"bundleId\": \"medium_1_0\",
                \"name\": \"Object Storage 100GB\",
                \"price\": 3.0,
                \"storagePerMonthInGb\": 100,
                \"transferPerMonthInGb\": 250,
                \"isActive\": true
            },
            {
                \"bundleId\": \"large_1_0\",
                \"name\": \"Object Storage 250GB\",
                \"price\": 5.0,
                \"storagePerMonthInGb\": 250,
                \"transferPerMonthInGb\": 500,
                \"isActive\": true
    ```
    Change the \"bundleId\" to the size of storage you need.

    Repeat and create all the S3 buckets that you need for Lightsail.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'SC-28', 'AC-11 b']
  tag cci:                   ['CCI-000213', 'CCI-001199', 'CCI-000056']
  tag cis_number:            '5.8'
  tag cis_rid:               '5.8'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0508r1_rule'
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
      its('buckets_without_attached_instance') { should be_empty }
    end
  end
end
