# encoding: UTF-8

control 'C-12.4' do
  title 'Ensure least privilege is used with Lambda function access'
  desc  "
    Lambda is fully integrated with IAM, allowing you to control precisely what each Lambda function can do within the AWS Cloud.  As you develop a Lambda function, you expand the scope of this policy to enable access to other resources. For example, for a function that processes objects put into an S3 bucket, it requires read access to objects stored in that bucket. Do not grant the function broader permissions to write or delete data, or operate in other buckets.

    You can use AWS Identity and Access Management (IAM) to manage access to the Lambda API and resources like functions and layers. For users and applications in your account that use Lambda, you manage permissions in a permissions policy that you can apply to IAM users, groups, or roles. To grant permissions to other accounts or AWS services that use your Lambda resources, you use a policy that applies to the resource itself.
  "
  desc  'rationale', "
    Lambda is fully integrated with IAM, allowing you to control precisely what each Lambda function can do within the AWS Cloud.  As you develop a Lambda function, you expand the scope of this policy to enable access to other resources. For example, for a function that processes objects put into an S3 bucket, it requires read access to objects stored in that bucket. Do not grant the function broader permissions to write or delete data, or operate in other buckets.

    You can use AWS Identity and Access Management (IAM) to manage access to the Lambda API and resources like functions and layers. For users and applications in your account that use Lambda, you manage permissions in a permissions policy that you can apply to IAM users, groups, or roles. To grant permissions to other accounts or AWS services that use your Lambda resources, you use a policy that applies to the resource itself.
  "
  desc  'check', "
    Determining the exact permissions required is a manual process and can be challenging, since IAM permissions are very granular and they control access to both the data plane and control plane.

    Please refer to the references section below for useful documentation on developing the correct IAM policies for Lambda.
  "
  desc  'fix', "
    As building out the IAM permissions for Lambda here are some things to consider.
    - Set granular IAM permissions for Lambda functions.
    - Limit user access via IAM permissions to only necessary resources and operations.
    - Remove unused or outdated IAM Users, Roles and Permissions.
    - Periodically review and adjust IAM permissions.
    - Do not allow all-access permissions for Lambda functions as a short cut.\"
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-2 (2)']
  tag cci:                   ['CCI-000213', 'CCI-001682']
  tag cis_number:            '12.4'
  tag cis_rid:               '12.4'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1204r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('lambda')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("LAMBDA out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  describe aws_lambda_compliance(regions: input('scan_regions')) do
    its('functions_with_admin_policy') { should be_empty }
  end
end
