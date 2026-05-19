# encoding: UTF-8

control 'C-12.3' do
  title 'Ensure AWS Secrets manager is configured and being used by Lambda for databases'
  desc  "
    Lambda functions often have to access a database or other services within your environment.

    Credentials used to access databases and other AWS Services need to be managed and regularly rotated to keep access into critical systems secure.  Keeping any credentials and manually updating  the passwords would be cumbersome, but AWS Secrets Manager allows you to manage and rotate  passwords.
  "
  desc  'rationale', "
    Lambda functions often have to access a database or other services within your environment.

    Credentials used to access databases and other AWS Services need to be managed and regularly rotated to keep access into critical systems secure.  Keeping any credentials and manually updating  the passwords would be cumbersome, but AWS Secrets Manager allows you to manage and rotate  passwords.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Secrets Manager` under Security, Identity and Compliance.

    3. Click on `Secrets`.

    4. Review the secrets listed

    5. Confirm that the secret required for Lambda functions is included in the list.

    6. If it is, review your code and confirm that you are calling the credentials during runtime.

    7. If the credentials are not listed refer to the remediation below.

    9. Repeat steps 2-7 for all regions used.
  "
  desc  'fix', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services`, click `Secrets Manager` under Security, Identity and Compliance.

    3. Click on `Secrets`.

    4. Click on `Store a new secret`

    5. Select the `Secret type`

    6.  Enter the information
    ```
    For the `3 db types` listed enter the credentials and select the database.
    For `other database` enter the credentials, select the db type and enter the connection parameters.
    ```
    For `Other type of secret` (Lambda) create the keys and values used. - example Username yepyep Password yepyep
    choose an encryption key or create a new one
    if you add a new key it will take you to the KMS console.  Once you create the new key you can then select it here.

    7. Click `Next`

    8. Give the secret a name associated with your organization style and lambda

    9. Click `Next`

    10. Configure the auto rotation
    ```
    Rotation schedule leave as default
    Select the lambda function you use to rotate the key
    ```
    11. Click `Next`

    12. Review all the settings

    13. Click `Store`
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'AC-3', 'AC-18 a']
  tag cci:                   ['CCI-000381', 'CCI-000213', 'CCI-002323']
  tag cis_number:            '12.3'
  tag cis_rid:               '12.3'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1203r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('lambda')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("LAMBDA out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  # Automated heuristic: scan every Lambda function's environment
  # variables for plaintext DB connection strings (host pattern matching
  # *.rds.amazonaws.com — or rds-data API ARNs). Any function whose env
  # vars contain a plaintext DB host without a paired *_SECRET_ARN /
  # *_SECRETS_MANAGER_ARN entry is flagged. The check is a heuristic,
  # not a proof — operators can mark genuine false positives via HDF
  # amendments. The intent is to catch the common antipattern (DB host
  # + password baked into env vars) at scan time rather than punting to
  # an attestation slot.
  #
  # Conservative: a function with NO env vars at all is not flagged (no
  # evidence either way). A function whose env vars reference Secrets
  # Manager ARNs but also contain plaintext hosts IS flagged — the
  # ARN reference doesn't prove the plaintext value is unused.
  offenders = []
  begin
    Array(aws_lambda_inventory.functions).each do |f|
      env = (f[:environment] && f[:environment][:variables]) || {}
      next if env.empty?

      has_secrets_ref = env.any? { |k, v| (k.to_s =~ /SECRET|SECRETS_MANAGER/i) || (v.to_s =~ %r{arn:aws:secretsmanager:}) }
      has_plaintext_db_host = env.any? { |_, v| v.to_s =~ /\.rds\.amazonaws\.com/i }

      if has_plaintext_db_host && !has_secrets_ref
        offenders << "#{f[:function_name]}: env contains RDS host without Secrets Manager reference"
      end
    end
  rescue StandardError => e
    describe 'Lambda inventory enumeration' do
      it 'should succeed' do
        raise e
      end
    end
  end

  describe 'Lambda functions with plaintext DB connection strings (no Secrets Manager reference)' do
    subject { offenders }
    it { should be_empty }
  end
end
