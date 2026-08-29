# encoding: UTF-8

control 'C-5.12' do
  title 'Change the auto-generated password for Windows based instances.'
  desc  "
    When you create a Windows Server-based instance, Lightsail randomly generates a long password that is hard to guess. You use this password uniquely with your new instance. You can use the default password to connect quickly to your instance using remote desktop (RDP). You are always logged in as the Administrator on your Lightsail instance.

    Like any password it should be changed from the default and over time.  The randomly generated password can be hard to remember and if anyone gains access to your AWS Lightsail environment they can utilize that to access your instances.  For this reason you should change the password to something you can remember.
  "
  desc  'rationale', "
    When you create a Windows Server-based instance, Lightsail randomly generates a long password that is hard to guess. You use this password uniquely with your new instance. You can use the default password to connect quickly to your instance using remote desktop (RDP). You are always logged in as the Administrator on your Lightsail instance.

    Like any password it should be changed from the default and over time.  The randomly generated password can be hard to remember and if anyone gains access to your AWS Lightsail environment they can utilize that to access your instances.  For this reason you should change the password to something you can remember.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Windows Instance` you want to review.

    5. Make sure the instance status is `running`.

    6. Connect to the `instance` using `Connect using RDP`.

    7. Log in using the credentials provided within the Lightsail console set for this instance.

    8. If you are successful and based on your password change policy it is required that you change/update the password refer to the remediation below.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Windows Instance` you want to review.

    5. Make sure the instance status is `running`.

    6. Connect to the `instance` using `Connect using RDP`.

    7. Log in using the credentials provided within the Lightsail console set for this instance.

    8. Use the Windows Server password manager to change your password securely by press `Ctrl + Alt + Del`

    9. Then choose `Change a password`.
     Be sure to keep a record of your password, because Lightsail doesn't store the new password you are setting.

    10. Type in the `New Password`

    11.  Click `Save`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-18 a']
  tag nist_r4:               ['AC-18 a']
  tag cci:                   ['CCI-002323']
  tag cis_number:            '5.12'
  tag cis_rid:               '5.12'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0512r1_rule'
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

  describe 'Windows Lightsail auto-generated password rotation' do
    skip "Requires manual review and attestation provided for this control (the Windows-instance auto-generated administrator password is not retrievable from the AWS API after creation — operators attest from their post-launch credential-rotation runbook)."
  end
end
