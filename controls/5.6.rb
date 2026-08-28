# encoding: UTF-8

control 'C-5.6' do
  title 'Disable IPv6 Networking if not in use within your organization.'
  desc  "
    Any protocols enable within Lightsail by default that aren't being used should be disabled.

    Any ports enable within Lightsail by default are open and exposed to the world. This can result in outside traffic trying to access or even deny access to the Lightsail instances. Removing and disabling a protocol when not in use even if restricted by IP address is the safest solution especially when it is not required for access.
  "
  desc  'rationale', "
    Any protocols enable within Lightsail by default that aren't being used should be disabled.

    Any ports enable within Lightsail by default are open and exposed to the world. This can result in outside traffic trying to access or even deny access to the Lightsail instances. Removing and disabling a protocol when not in use even if restricted by IP address is the safest solution especially when it is not required for access.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Windows or Linux Instance` you want to review.

    5. Go to the Networking section.

    6. Under IPv6 networking confirm that it reads `IPv6 networking is disabled`.

    7. If it reads `IPv6 networking is enabled` refer to the remediation below.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Windows or Linux Instance` you want to review.

    5. Go to the Networking section.

    6. Under IPv6 networking click on the check mark next to `IPv6 networking is enabled`.

    7. In the `Disable IPv6 for this instance?`

    8. Click on `Yes, disable`
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_number:            '5.6'
  tag cis_rid:               '5.6'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0506r1_rule'
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
      its('instances_with_ipv6_enabled') { should be_empty }
    end
  end
end
