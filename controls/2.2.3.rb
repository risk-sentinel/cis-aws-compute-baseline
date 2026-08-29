# encoding: UTF-8

control 'C-2.2.3' do
  title 'Ensure EBS volume snapshots are encrypted'
  desc  "
    Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service.

    Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.
  "
  desc  'rationale', "
    Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service.

    Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.
  "
  desc  'check', "
    From Console:

    1. Login to the EC2 console using `https://console.aws.amazon.com/ec2/`
 
    2. Under `Elastic Block Store`, click `Snapshots`.

    3. Click the snapshot you want to review.

    4. Select the `Description` tab.

    5. Review the `Encryption` setting.

    6. If it reads `encrypted` you are all set.

    If it is set to `Not Encrypted` refer to the remediation below.

    Note: EBS snapshot volume encryption is configured per snapshot.

    From Command Line:

    1. Run describe-snapshots
    ```
    aws ec2 describe-snapshots --owner-ids --filter Name=status,Values=completed --query \"Snapshots[*].{ID:SnapshotId}\"
    ```
    2. This will provide a list of all the snapshots associated with that account in the region.

    3. For every snapshot listed - Run - describe-snapshots
    ```
    aws ec2 describe-snapshots --snapshot-id --query \"Snapshots[*].{Encrypt:Encrypted}\"
    ```
    4. If the output reads `\"Encrypt\": true`, Encryption is set on the snapshot.

    If the output reads `\"Encrypt\": false` refer to the remediation below.

    Note: EBS snapshot volume encryption is configured per snapshot.
  "
  desc  'fix', "
    From Console:

    1. Login to the EC2 console using `https://console.aws.amazon.com/ec2/`

    2. Under `Elastic Block Store, click `Snapshots`.

    3. Select the snapshot you want to encrypt.

    4. Click on `Actions` select `Copy`.
    ```
    Confirm `Snapshot ID`
    Set the `Destination Region`
    Update the `Description`
    Select the check box for `Encryption`
    ```
    5. Check the box for `Encrypt this snapshot`

    6. Set the `Master Key`

    7. Click on `Copy`

    8. Repeat steps 3-7 for the snapshots that need to be encrypted.

    9. Delete any of the unencrypted snapshots that are not longer needed.

    Note: EBS snapshot volume encryption is configured per snapshot.

    From Command Line:

    Using the snapshot ids gathered from the Audit section
    1. Run - copy-snapshot
    ```
    aws ec2 copy-snapshot --source-region --source-snapshot-id --description \"Name of the new snapshot\" --encrypted
    ```
    2. This will copy the existing unencrypted snapshot and set it to encrypted
    The output will show the new SnapshotId

    3. Run - describe-snapshots
    ```
    aws ec2 describe-snapshots --owner-ids --filter Name=status,Values=completed --query \"Snapshots[*].{ID:SnapshotId}\"
    ```
    Once the new Snapshot shows in the list confirm encryption is set

    4. Run - describe-snapshots
    ```
    aws ec2 describe-snapshots --snapshot-id --query \"Snapshots[*].{Encrypt:Encrypted}\"
    ```

    5.Repeat steps 1-4 for the snapshots that need to be encrypted.

    Delete snapshots that are no longer needed.

    6. Run - delete-snapshot
    ```
    aws ec2 delete-snapshot --snapshot-id ```

    7. Repeat for all unencrypted snapshots that have been copied and encrypted.

    Note: EBS snapshot volume encryption is configured per snapshot.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '2.2.3'
  tag cis_rid:               '2.2.3'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-020203r1_rule'
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

  describe 'EBS snapshots with encryption disabled' do
    subject { aws_ebs_snapshots_multi_region(regions: input('scan_regions')).where(encrypted: false).snapshot_ids }
    it { should be_empty }
  end
end
