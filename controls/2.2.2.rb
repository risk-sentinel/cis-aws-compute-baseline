# encoding: UTF-8

control 'C-2.2.2' do
  title 'Ensure Public Access to EBS Snapshots is Disabled'
  desc  "
    To protect your data disable the public mode of EBS snapshots.

    This protects your data so that it is not accessible to all AWS accounts preventing accidental access and leaks.
  "
  desc  'rationale', "
    To protect your data disable the public mode of EBS snapshots.

    This protects your data so that it is not accessible to all AWS accounts preventing accidental access and leaks.
  "
  desc  'check', "
    Perform the following to determine if a snapshot is shared publicly:

    From the Console

    1. Login to the EC2 console at `https://console.aws.amazon.com/ec2/`.

    2. In the left pane click `Snapshots`.

    3. Select the `snapshot` then click `Actions`, `Modify Permissions`.

    4. Confirm that the snapshot is set to `Private`

    5. Repeat for any additional Snapshots, Regions and AWS accounts.

    If the snapshot is set to public refer to the remediation below.

    From the CLI

    1. For each snapshot, run 
    ```
    aws ec2 describe-snapshot-attribute \\
        --snapshot-id \\
        --attribute createVolumePermission
    ```
    2. Validate `Group` is not set to all.
  "
  desc  'fix', "
    Perform the following to set a snapshot to private:

    From the Console

    1. Login to the EC2 console at `https://console.aws.amazon.com/ec2/`.

    2. In the left pane click `Snapshots`.

    3. Select the `snapshot` then click 'Actions`, `Modify Permissions`.

    4. Click the radio button for `Private`

    5. Click `Save`

    6. Repeat for any additional Snapshots, Regions and AWS accounts.

    From the CLI

    1. For each snapshot, run 
    ```
    aws ec2 modify-snapshot-attribute \\
       --snapshot-id \\
       --attribute createVolumePermission \\
       --operation remove --group-name all   
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.2.2'
  tag cis_rid:               '2.2.2'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-020202r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('ec2')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("EC2 out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  describe aws_ebs_snapshot_public_access(regions: input('scan_regions')) do
    its('public_snapshots') { should be_empty }
  end
end
