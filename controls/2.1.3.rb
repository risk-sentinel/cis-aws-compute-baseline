# encoding: UTF-8

control 'C-2.1.3' do
  title 'Ensure Only Approved Amazon Machine Images (AMIs) are Used'
  desc  "
    Ensure that all base AMIs utilized are approved for use by your organization.

    An approved AMI is a base EC2 machine image that is a pre-configured OS configured to run your application. Using approved AMIs helps enforce consistency and security.
  "
  desc  'rationale', "
    Ensure that all base AMIs utilized are approved for use by your organization.

    An approved AMI is a base EC2 machine image that is a pre-configured OS configured to run your application. Using approved AMIs helps enforce consistency and security.
  "
  desc  'check', "
    Perform the following to confirm only approved AMIs are being used.

    From the Console:

    1. Login to the EC2 console at `https://console.aws.amazon.com/ec2/`.

    2. In the left pane click on `Images`.

    3. Then choose `AMIs`

    4. Confirm that `Owned by me` is selected

    5. Review the list of AMIs.

    6. Confirm that the AMIs listed are all approved for use

    7. In the left pane click on `Instances`

    8. Then choose `Instances`

    9. Select the EC2 instance for review.

    10. In the Details tab review:
    ```
         AMI Name

         AMI location
    ```
    11. Confirm that the AMI name matches an approved AMI and the AMI location is within your account.

    12. Repeat steps 9 - 11 to verify the AMI is approved

    Repeat the process for all other regions.

    If any of the AMIs are not approved refer to the remediation below.
  "
  desc  'fix', "
    Perform the following to remove unauthorized AMIs.

    From the Console:

    1. Login to the EC2 console at `https://console.aws.amazon.com/ec2/`.

    2. In the left pane click on `Images`.

    3. Then choose `AMIs`

    4. Confirm that `Owned by me` is selected

    5. Review the list of AMIs.

    6. Confirm that the AMIs listed are all approved for use

    7. If an AMI is listed that is not approved select it.

    8. Click on `Actions` and choose `Deregister`

    After all unauthorized AMIs have been De-registered review all EC2 instances.

    1. Click on `Instances`

    2. Then choose `Instances`

    3. Select the `EC2 instance` for review.

    4. In the `Details` tab review:
    ```
         AMI Name

         AMI location
    ```
    5. If this information is listed as not available this instance was built with an unauthorized AMI.

    6. Follow organization steps to secure this instance and replace it with an instance built from an approved AMI if applicable.

    7. Repeat steps 3 - 6 to verify all instance have been created with approved AMIs

    Repeat the process for all other regions.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-8 a 1']
  tag cci:                   ['CCI-000389']
  tag cis_number:            '2.1.3'
  tag cis_rid:               '2.1.3'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-020103r1_rule'
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

  approved = Array(input('approved_amis')).map(&:to_s)
  amis = aws_ec2_amis_in_use(
    regions:        compute_scan_regions,
    trusted_owners: Array(input('trusted_ami_owner_ids')).map(&:to_s),
  )

  if amis.connection_error
    describe 'AMI provenance' do
      skip "AMIs in use could not be enumerated: #{amis.connection_error}"
    end
  else
    # Provenance signals that need no configuration. These assert something on
    # the first run, before anyone has curated a catalogue -- which is the point,
    # since an empty catalogue is exactly the state an adopter starts in.
    describe amis do
      its('public_amis')          { should be_empty }
      its('deregistered_amis')    { should be_empty }
      its('untrusted_owner_amis') { should be_empty }
    end

    if approved.empty?
      # Still a configuration failure rather than an attestation slot -- but now
      # the failure names the AMIs actually in use, so the operator can populate
      # the catalogue from it instead of guessing.
      describe 'approved_amis input' do
        it 'must be populated for CIS 2.1.3 to evaluate' do
          expect(approved).not_to be_empty,
            "Set approved_amis to the AMI IDs the organization has vetted. " \
            "Discovered in use right now: #{amis.inventory.join(' | ')}. " \
            "Empty input means CIS 2.1.3 has no allowlist to evaluate against; " \
            "flagged as FAIL rather than silently skipping."
        end
      end
    else
      describe "AMIs outside the approved catalogue" do
        subject { amis.amis_not_in(approved) }
        it { should be_empty }
      end
    end
  end
end
