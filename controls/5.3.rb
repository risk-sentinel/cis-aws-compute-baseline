# encoding: UTF-8

control 'C-5.3' do
  title 'Disable SSH and RDP ports for Lightsail instances when not needed.'
  desc  "
    Any ports enable within Lightsail by default are open and exposed to the world.  For SSH and RDP access you should remove and disable these ports when not is use.

    Any ports enable within Lightsail by default are open and exposed to the world.  This can result in outside traffic trying to access or even deny access to the Lightsail instances. Removing and disabling a protocol when not in use even if restricted by IP address is the safest solution especially when it is not required for access.
  "
  desc  'rationale', "
    Any ports enable within Lightsail by default are open and exposed to the world.  For SSH and RDP access you should remove and disable these ports when not is use.

    Any ports enable within Lightsail by default are open and exposed to the world.  This can result in outside traffic trying to access or even deny access to the Lightsail instances. Removing and disabling a protocol when not in use even if restricted by IP address is the safest solution especially when it is not required for access.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Windows or Linux Instance` you want to review.

    5. Go to the Networking section.

    6. If it is a Windows instance confirm that SSH has been removed.  If it is a Linux instance confirm RDP has been removed.

    7. If either still exists in the IPV4 Firewall list refer to the remediation below.

    8. If the server needs HTTP, TCP Port 80 confirm that the application forwards Port 80 to HTTPS, TCP Port 443.

    9. If the server does not need HTTP refer to the remediation below.

    10. Confirm that there are no other unused or unneeded ports.

    11. If the system has other ports that are not required or in use refer to the remediation below.

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
    2. Run `aws lightsail get-instance-port-states` for each instance listed above

    ```
    aws lightsail get-instance-port-states --instance-name ```
    This command will provide a list of available Ports for the Instance name.
    ```
    \"portStates\": [
            {
                \"fromPort\": 80,
                \"toPort\": 80,
                \"protocol\": \"tcp\",
                \"state\": \"open\",
                \"cidrs\": [
                    \"0.0.0.0/0\"
                ],
                \"cidrListAliases\": []
            },
            {
                \"fromPort\": 22,
                \"toPort\": 22,
                \"protocol\": \"tcp\",
                \"state\": \"open\",
                \"cidrs\": [
                    \"0.0.0.0/0\"
                ],
                \"cidrListAliases\": []
            },
            {
                \"fromPort\": 443,
                \"toPort\": 443,
                \"protocol\": \"tcp\",
                \"state\": \"open\",
                \"cidrs\": [
                    \"0.0.0.0/0\"
                ],
                \"cidrListAliases\": []
    ```

    If it is a Linux host and has Port 3398 listed, HTTP Port 80 listed or any other ports listed that are not required refer to the remediation below.
    If it is a Windows host and has Port 22 listed, HTTP Port 80 listed or any other ports listed that are not required refer to the remediation below.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Windows or Linux Instance` you want to review.

    5. Go to the Networking section.

    6. If it is a Windows instance confirm that SSH has been removed.  If it is a Linux instance confirm RDP has been removed.

    7. If either ssh(Port 22) is in the Windows system and RDP(Port 3389) is in the Linux system click the bucket icon to delete it.

    8. If the server needs HTTP, TCP Port 80 confirm that the application forwards Port 80 to HTTPS, TCP Port 443.

    9. If the server does not need HTTP click the bucket icon to delete it.

    10. Confirm that there are no other unused or unneeded ports.

    11. If the system has other ports that are not required or in use click the bucket icon to delete it.

    From the Command Line:

    1. Run `aws lightsail close-instance-public-ports`

    For Windows:
    ```
    aws lightsail close-instance-public-ports --instance-name --port-info fromPort=22,protocol=TCP,toPort=22
    ```
    For Linux:
    ```
    aws lightsail close-instance-public-ports --instance-name --port-info fromPort=3389,protocol=TCP,toPort=3389
    ```
    For HTTP:
    ```
    aws lightsail close-instance-public-ports --instance-name --port-info fromPort=80,protocol=TCP,toPort=80
    ```
    2. Repeat for all instance names identified in the audit that have SSH, RDP or HTTP's open and are not required based on the OS or the use of the system.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_number:            '5.3'
  tag cis_rid:               '5.3'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0503r1_rule'
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
    allowed_ssh_cidrs:  input('lightsail_allowed_ssh_cidrs'),
    allowed_rdp_cidrs:  input('lightsail_allowed_rdp_cidrs'),
  )
  if inv.connection_error
    describe 'Amazon Lightsail inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('instances_with_ssh_or_rdp_open') { should be_empty }
    end
  end
end
