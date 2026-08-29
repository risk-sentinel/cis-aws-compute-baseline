# encoding: UTF-8

control 'C-5.10' do
  title 'Enable storage bucket access logging'
  desc  "
    Access logging provides detailed records for the requests that are made to this bucket.  This information can include the request type, the resources that are specified in the request, and the time and date that the request was processed. Access logs are useful for many applications.

    Access log information is useful in security and access audits.
  "
  desc  'rationale', "
    Access logging provides detailed records for the requests that are made to this bucket.  This information can include the request type, the resources that are specified in the request, and the time and date that the request was processed. Access logs are useful for many applications.

    Access log information is useful in security and access audits.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select `Storage`.

    5. All Lightsail buckets are listed here.

    6. Click on a bucket name

    7. Click `Logging`.

    8. Confirm that Access logging is set to active.  If it is set to inactive refer to the remediation below.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select `Storage`.

    5. All Lightsail buckets are listed here.

    6. Click on a bucket name

    7. Click `Logging`.

    8. Click on the X next to `Access logging is inactive`

    9. Select a different bucket specific to store the logging information.

    10. Note the path or create a path that matches your organization style.

    11. Click save

    12. Click OK

    13. Repeat steps 6-12 for all Lightsail buckets.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '5.10'
  tag cis_rid:               '5.10'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0510r1_rule'
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

  inv = aws_lightsail_inventory(regions: compute_scan_regions)
  if inv.connection_error
    describe 'Amazon Lightsail inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('buckets_without_access_log') { should be_empty }
    end
  end
end
