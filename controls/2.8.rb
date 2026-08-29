# encoding: UTF-8

control 'C-2.8' do
  title 'Ensure the Use of IMDSv2 is Enforced on All Existing Instances'
  desc  "
    Ensure the Instance Metadata Service Version 2 (IMDSv2) method is enabled on all running instances.

    The IMDSv2 method uses session-based controls to help protect access and control of Amazon Elastic Compute Cloud (Amazon EC2) instance metadata. With IMDSv2, controls can be implemented to restrict changes to instance metadata.
  "
  desc  'rationale', "
    Ensure the Instance Metadata Service Version 2 (IMDSv2) method is enabled on all running instances.

    The IMDSv2 method uses session-based controls to help protect access and control of Amazon Elastic Compute Cloud (Amazon EC2) instance metadata. With IMDSv2, controls can be implemented to restrict changes to instance metadata.
  "
  desc  'check', "
    From the Console:

    1. At this time the instance metadata setting for existing instances can only be reviewed and confirmed using AWS CLI.

    From the CLI

    1. Run the describe-instances command
    ```
    aws ec2 describe-instances --region us-east-1 --output text --filter \"Name=metadata-options.http-tokens,Values=optional\" --query \"Reservations[*].Instances[*].{Instance:InstanceId}\"
    ```
    2 The output should look like this:
    ```
    i-1234567abcdefghi0
    i-1234567abcdefghi0
    i-1234567abcdefghi0
    ```
    The list above contains all the instances that have the metadata version set to optional which means either IMDSv1 or INDSv2 an be used.  Refer to the remediation below.

    Repeat steps 1 - 2 for the other AWS regions.
  "
  desc  'fix', "
    From the Console:

    1. At this time the instance metadata setting for existing instances can only be changed using AWS CLI.

    From the CLI

    1. Run the modify-instance-metadata-options command using the list of Instances collect in the audit
    ```
    aws ec2 modify-instance-metadata-options --instance-id i-1234567abcdefghi0 --http-tokens required --http-endpoint enabled
    ```
    2. The output should show the information for the instance and the metadata changes:
    ```
    {
        \"InstanceId\": \"i-1234567abcdefghi0\",
        \"InstanceMetadataOptions\": {
            \"State\": \"pending\",
            \"HttpTokens\": \"required\",
            \"HttpPutResponseHopLimit\": 1,
            \"HttpEndpoint\": \"enabled\"
        }
    }
    ```
    3. Repeat for the other instances and regions collected during the audit.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.8'
  tag cis_rid:               '2.8'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0208r1_rule'
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

  describe 'EC2 instances without IMDSv2 enforced (metadata_options.http_tokens != required)' do
    subject { aws_ec2_inventory.instances_without_imdsv2 }
    it { should be_empty }
  end
end
