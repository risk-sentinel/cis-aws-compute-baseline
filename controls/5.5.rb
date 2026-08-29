# encoding: UTF-8

control 'C-5.5' do
  title 'Ensure RDP is restricted to only IP address that should have this access.'
  desc  "
    Any ports enable within Lightsail by default are open and exposed to the world. For SSH and RDP access you should identify which IP address need access.

    Any ports enable within Lightsail by default are open and exposed to the world. This can result in outside traffic trying to access or even deny access to the Lightsail instances. Removing and adding approved IP address required for access.
  "
  desc  'rationale', "
    Any ports enable within Lightsail by default are open and exposed to the world. For SSH and RDP access you should identify which IP address need access.

    Any ports enable within Lightsail by default are open and exposed to the world. This can result in outside traffic trying to access or even deny access to the Lightsail instances. Removing and adding approved IP address required for access.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Windows Instance` you want to review.

    5. Go to the Networking section.

    6. Confirm that the RDP Port is restricted to an IP address
    ```
    Application	Protocol	Port or range / Code	Restricted to	
    RDP		TCP		3389			101.221.11.11
    ```
    7. If RDP is needed and it is open to `Any IPv4 address` refer to the remediation below.

    From the Command Line:

    1. Run `aws lightsail get-instances`

    ```
    aws lightsail get-instances --query \"instances[*].name\"
    ```
    This command will provide a list of Instance names.
    ```
    \"WordPress-1\",
    \"Windows_Server_2019-1\"
    ```
    2. Run `aws lightsail get-instance-port-states` for any Windows instances listed

    ```
    aws lightsail get-instance-port-states --instance-name ```
    This command will provide a list of available Ports for the Instance name.
    ```
            {
                \"fromPort\": 3389,
                \"toPort\": 3389,
                \"protocol\": \"tcp\",
                \"state\": \"open\",
                \"cidrs\": [
                    \"0.0.0.0/0\"
                ],
                \"cidrListAliases\": []
            },
    ```

    3. Review the Port 22 settings and confirm that the only IP Addresses that should have access to the instance are listed in the cidrs as shown above.

    4. If it is open to all ports (0.0.0.0/0) of there is an IP address listed that shouldn't have access refer to the remediation below.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Windows Instance` you want to review.

    5. Go to the Networking section.

    6. Under IPv4 networking find the SSH rule as shown below.
    ```
    Application	Protocol	Port or range / Code	Restricted to	
    RDP		TCP		3389			Any IPv4 address
    ```
    7. Click on the edit icon

    8. Click on the check box next to Restrict to IP address

    9. Under `Source IP address (192.0.2.0) or range (192.0.2.0-192.0.2.255 or 192.0.2.0/24)` type the IP address' you want.

    From the Command Line:

    1. Run `aws lightsail put-ins`

    ```
    aws lightsail put-instance-public-ports --instance-name --port-info fromPort=3389,protocol=TCP,toPort=3389,cidrs=110.111.221.100/32,110.111.221.202/32
    ```
    This command will enter the IP addresses that should have access to the instances identified above in the Audit.

    2. Run `aws lightsail get-instance-port-states` for the Windows instance to confirm the new setting.

    ```
    aws lightsail get-instance-port-states --instance-name ```
    This command will provide a list of available Ports and show how the cidr value for Port 3389 is now set.
    ```
    \"portStates\": [
            {
                \"fromPort\": 3389,
                \"toPort\": 3389,
                \"protocol\": \"tcp\",
                \"state\": \"open\",
                \"cidrs\": [
                    \"110.111.221.100/32\",
                    \"110.111.221.202/32\"
                ],
                \"cidrListAliases\": []
            }
    ```

    3. Repeat the remediation below for all other Windows instances identified in the Audit.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '5.5'
  tag cis_rid:               '5.5'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0505r1_rule'
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

  inv = aws_lightsail_inventory(
    regions:            input('scan_regions'),
    allowed_rdp_cidrs:  input('lightsail_allowed_rdp_cidrs'),
  )
  if inv.connection_error
    describe 'Amazon Lightsail inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('instances_with_rdp_open_to_world') { should be_empty }
    end
  end
end
