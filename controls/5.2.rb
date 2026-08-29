# encoding: UTF-8

control 'C-5.2' do
  title 'Change default Administrator login names and passwords for applications'
  desc  "
    Change the default settings for the administrator login names and passwords of the application software that you install on Lightsail instances.

    Default administrator login names and passwords for applications used on Lightsail instances can be used by hackers and individuals to break into your servers.
  "
  desc  'rationale', "
    Change the default settings for the administrator login names and passwords of the application software that you install on Lightsail instances.

    Default administrator login names and passwords for applications used on Lightsail instances can be used by hackers and individuals to break into your servers.
  "
  desc  'check', "
    To confirm that you have updated or changed the default administrator name and password for any application you are using is a manual process.  Often dependent on the application itself and the operating system you are utilizing for the Lightsail instance.

    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Instance` you want to review.

    5. Make sure the instance status is `running`.

    6. Connect to the `instance`.

    7. Depending on the instance OS and the application you are running determine what the default administrator name is set to and what the password is.

    8. If the `default administrator` username and or password is still at the default settings please refer to the remediation below.

    9. Repeat steps no. 4 - 8 to verify if any Lightsail instances require application updates.
  "
  desc  'fix', "
    To process and apply the latest updates for the application you are using is a manual process.  Often dependent on the application itself and the operating system you are utilizing for the Lightsail instance.

    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Instance` you want to update the `default administrator` settings.

    5. Make sure the instance status is `running`.

    6. Click on `Snapshots`

    7. Under `Manual snapshots` click on `+ Create snapshot`

    8. Give it a name you will recognize

    9. Click on `create`
    ```
    while in process it will show Snapshotting...
    ```
    10. Once the date and time and snapshot name appears it is completed.

    11. Click on `Connect`

    12. Run the process to change either the `default administrator` name or password or both.

    13. Repeat steps no. 4 - 12 to apply any application `default administrator` changes required on the Lightsail instances that you are running.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-18 a']
  tag nist_r4:               ['AC-18 a']
  tag cci:                   ['CCI-002323']
  tag cis_number:            '5.2'
  tag cis_rid:               '5.2'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0502r1_rule'
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

  describe 'Lightsail default-credential rotation' do
    skip "Requires manual review and attestation provided for this control (in-app default admin credentials for software running on Lightsail instances are not exposed by the AWS API — operators attest from their credential-rotation runbook for each Lightsail blueprint's hosted application)."
  end
end
