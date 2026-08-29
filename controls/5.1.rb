# encoding: UTF-8

control 'C-5.1' do
  title 'Apply updates to any apps running in Lightsail'
  desc  "
    Amazon Lightsail is a virtual private server (VPS) provider and is the easiest way to get started with AWS for developers, small businesses, students, and other users who need a solution to build and host their applications on cloud.

    Lightsail offers a range of operating system and application templates that are automatically installed when you create a new Lightsail instance. Application templates include WordPress, Drupal, Joomla!, Ghost, Magento, Redmine, LAMP, Nginx (LEMP), MEAN, Node.js, Django, and more.  You can install additional software on your instances by using the in-browser SSH or your own SSH client.
  "
  desc  'rationale', "
    Amazon Lightsail is a virtual private server (VPS) provider and is the easiest way to get started with AWS for developers, small businesses, students, and other users who need a solution to build and host their applications on cloud.

    Lightsail offers a range of operating system and application templates that are automatically installed when you create a new Lightsail instance. Application templates include WordPress, Drupal, Joomla!, Ghost, Magento, Redmine, LAMP, Nginx (LEMP), MEAN, Node.js, Django, and more.  You can install additional software on your instances by using the in-browser SSH or your own SSH client.
  "
  desc  'check', "
    To confirm that you are running the latest version of the application you are using is a manual process.  Often dependent on the application itself and the operating system you are utilizing for the Lightsail instance.

    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Instance` you want to review.

    5. Make sure the instance status is `running`.

    6. Connect to the `instance`.

    7. Depending on the instance OS and the application you are running determine what version it is and if there are any updates.

    8. If there are updates refer to the remediation below.

    9. Repeat steps no. 4 - 8 to verify if any Lightsail instances require application updates.
  "
  desc  'fix', "
    To process and apply the latest updates for the application you are using is a manual process.  Often dependent on the application itself and the operating system you are utilizing for the Lightsail instance.

    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Lightsail` under Compute.

    3. This will open up the Lightsail console.

    4. Select the `Instance` you want to update.

    5. Make sure the instance status is `running`.

    6. Click on `Snapshots`

    7. Under `Manual snapshots` click on `+ Create snapshot`

    8. Give it a name you will recognize

    9. Click on `create`
    ```
    while in process it will show 'Snapshotting...'
    ```
    10. Once the date and time and snapshot name appears it is completed.

    11. Click on `Connect`

    12. Run the updates for the application discovered above in the Audit.

    13. Repeat steps no. 4 - 12 to apply any application updates required on the Lightsail instances that you are running.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['MP-6 a', 'SI-2 a']
  tag ksi:                   ['KSI-CMT-VTD']
  tag nist_r4:               ['MP-6 a', 'SI-2 a']
  tag cci:                   ['CCI-001028', 'CCI-001225']
  tag cis_number:            '5.1'
  tag cis_rid:               '5.1'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0501r1_rule'
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

  describe 'Lightsail in-app update posture' do
    skip "Requires manual review and attestation provided for this control (in-app update state for software running on Lightsail instances is not exposed by the AWS API — operators attest from their patch / update review of each Lightsail blueprint's hosted application)."
  end
end
