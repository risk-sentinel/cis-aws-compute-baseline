# encoding: UTF-8

control 'C-2.1.1' do
  title 'Ensure Consistent Naming Convention is used for Organizational AMI'
  desc  "
    The naming convention for AMI (Amazon Machine Images) should be documented and followed for any AMI's created.

    The majority of AWS resources can be named and tagged.  Most organizations have already created standardize naming conventions, and have existing rules in effect.  They simply need to extend that for all AWS cloud resources to include Amazon Machine Images (AMI)
  "
  desc  'rationale', "
    The naming convention for AMI (Amazon Machine Images) should be documented and followed for any AMI's created.

    The majority of AWS resources can be named and tagged.  Most organizations have already created standardize naming conventions, and have existing rules in effect.  They simply need to extend that for all AWS cloud resources to include Amazon Machine Images (AMI)
  "
  desc  'check', "
    Perform the following to determine what AMI's are created:

    From the Console:

    1. Login to the EC2 console at `https://console.aws.amazon.com/ec2/`.

    2. In the left pane, under `Images`, click `AMIs`.

    3. Review the list of AMIs.

    4. Confirm that the AMI Name matches the organizational image naming policy.

    From the Command Line:

    1. Run aws ec2 describe-images.
    ```
    aws ec2 describe-images --owner self --region us-west-2
    ```
    2. Review the list of AMIs.

    3. Confirm that the AMI Name matches the organizational image naming policy.

    If any of the AMI Name's do not match the Organization policy refer to the remediation below.
  "
  desc  'fix', "
    If the AMI Name for an AMI doesn't follow Organization policy

    Perform the following to copy and rename the AMI:

    From the Console:

    1. Login to the EC2 console at `https://console.aws.amazon.com/ec2/`.

    2. In the left pane click `Images`, click `AMIs`.

    3. Select the AMI that does not comply to the naming policy.

    4. Click on `Actions`.

    5. Click on `Copy AMI`.
    ```
         Destination region - Select the region the AMI is in.

         Name - `Enter the new Name`

         Description - `Enter the new description`

         Encryption - `Select` if it matches your image policy
    ```
    6. Click on Copy AMI
    ```
    Once the AMI has finished copying.
    ```
    7. Select the AMI that does not comply to the naming policy.

    8. Click on `Actions`.

    9. Click on `Deregister`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-8 a 1']
  tag ksi:                   ['KSI-PIY-GIV']
  tag nist_r4:               ['CM-8 a 1']
  tag cci:                   ['CCI-000389']
  tag cis_number:            '2.1.1'
  tag cis_rid:               '2.1.1'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-020101r1_rule'
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

  pattern = input('approved_ami_naming_pattern').to_s
  if pattern.empty?
    # Empty input is a CONFIGURATION FAILURE, not an attestation slot.
    # CIS 2.1.1 requires the consumer to declare a naming convention;
    # without one, the control cannot evaluate compliance and must
    # not pass silently.
    describe 'approved_ami_naming_pattern input' do
      it 'must be populated for CIS 2.1.1 to evaluate' do
        expect(pattern).not_to be_empty,
          'Set approved_ami_naming_pattern to a regex (e.g., `^myorg-(prod|stage|dev)-[a-z0-9-]+-v[0-9]+$`) declaring the organizational AMI naming convention. Empty input means CIS 2.1.1 has no rule to evaluate against; flagged as FAIL rather than silently skipping.'
      end
    end
  else
    # Evaluated against the AMIs actually in use, discovered from the instances,
    # rather than against a declared catalogue. An image that never appears in
    # the catalogue but is running right now is exactly the one the naming
    # convention exists to surface.
    amis = aws_ec2_amis_in_use(regions: compute_scan_regions, naming_pattern: pattern)
    if amis.connection_error
      describe 'AMI naming convention' do
        skip "AMIs in use could not be enumerated: #{amis.connection_error}"
      end
    else
      describe "AMIs in use whose name does not match #{pattern}" do
        subject { amis.amis_not_matching_pattern }
        it { should be_empty }
      end
    end
  end
end
