# encoding: UTF-8

control 'C-5.11' do
  title 'Ensure your Windows Server based lightsail instances are updated with the latest security patches.'
  desc  "
    Windows server based Lightsail instances are still managed by the consumer and any security updates or patches have to be installed and maintained by the user.

    Windows Server-based Lightsail instances need to be updated with the latest security patches so they are not vulnerable to attacks. Be sure your server is configured to download and install updates.
  "
  desc  'rationale', "
    Windows server based Lightsail instances are still managed by the consumer and any security updates or patches have to be installed and maintained by the user.

    Windows Server-based Lightsail instances need to be updated with the latest security patches so they are not vulnerable to attacks. Be sure your server is configured to download and install updates.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Windows Instance` you want to review.

    5. Make sure the instance status is `running`.

    6. Connect to the `instance` using `Connect using RDP`.

    7. Log in using the credentials you have set for this instance.

    8. Open a command prompt

    9. Type sconfig, and then press Enter.
    ```
    Windows Update Settings are at number 5 and by default are set to Automatic.
    ```
    If this is the current setting continue with step 10.  If this is not the current setting refer to the remediation below and start at step 10.  

    10. To determine if any updates are required, type 6, and then press Enter.

    11. Type A to search for (A)ll updates in the new command window, and then press Enter.

    If any updates are required refer to the remediation below and start at step 14.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Windows Instance` you want to review.

    5. Make sure the instance status is `running`.

    6. Connect to the `instance` using `Connect using RDP`.

    7. Log in using the credentials you have set for this instance.

    8. Open a command prompt

    9. Type sconfig, and then press Enter.
    ```
    Windows Update Settings are at number 5 and by default are set to Automatic.
    ```
    If this is not the current setting continue with step 10.  If this is the current setting skip to step 12

    10. Type 5, and then press Enter.

    11. Type A for `Automatic` and then press Enter.  Wait until the setting is saved and you return back to the server configuration menu.

    12. Type 6, and then press Enter.

    13. Type A to search for (A)ll updates in the new command window, and then press Enter.

    14. Type A again to install (A)ll updates, and then press Enter.

    When finished, you see a message with the installation results and more instructions (if those apply).
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['MP-6 a', 'SI-2 a']
  tag ksi:                   ['KSI-CMT-VTD']
  tag nist_r4:               ['MP-6 a', 'SI-2 a']
  tag cci:                   ['CCI-001028', 'CCI-001225']
  tag cis_number:            '5.11'
  tag cis_rid:               '5.11'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0511r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('lightsail')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("LIGHTSAIL out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  describe 'Windows Server patch compliance for Lightsail instances' do
    skip "Requires manual review and attestation provided for this control (OS-level Windows patch posture for Lightsail Windows blueprints is not exposed by the AWS API — operators attest from their Windows Update / WSUS / SSM Patch Manager dashboard for the Lightsail Windows fleet)."
  end
end
