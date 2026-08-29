# encoding: UTF-8

control 'C-8.1' do
  title 'Ensure AWS Batch is configured with AWS Cloudwatch Logs.'
  desc  "
    You can configure Batch jobs to send log information to CloudWatch Logs.

    This enables you to view different logs from all your jobs in one convenient location.
  "
  desc  'rationale', "
    You can configure Batch jobs to send log information to CloudWatch Logs.

    This enables you to view different logs from all your jobs in one convenient location.
  "
  desc  'check', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/batch/`

    2. On the left hand side under `Console settings`, Click on `Permissions`

    3. Under `Job logs` section

    4. Confirm that `Authorize Batch to use Cloudwatch` is set with a green check.

    5. If is is showing a red X refer to the remediation below.
  "
  desc  'fix', "
    From the Console

    1. Login to the AWS Console using `https://console.aws.amazon.com/batch/`.

    2. In the left column under Console settings, Click on `Permissions`

    3. In the Job logs section click on `Edit`

    4. Click the `Authorize Batch to use CloudWatch`

    5. Click Save
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag nist_r4:               ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_number:            '8.1'
  tag cis_rid:               '8.1'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0801r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('batch')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("BATCH out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  offenders = aws_batch_job_definitions.where(statuses: 'ACTIVE').job_definition_names.each_with_object([]) do |name, acc|
    jd = aws_batch_job_definition(job_definition_name: name)
    next unless jd.exists?
    container = jd.container_properties || {}
    log_driver = container.dig(:log_configuration, :log_driver).to_s
    acc << "#{name}:log_driver=#{log_driver.empty? ? 'unset' : log_driver}" unless log_driver == 'awslogs'
  end

  describe 'AWS Batch active job definitions without awslogs log_driver in containerProperties' do
    subject { offenders }
    it { should be_empty }
  end
end
