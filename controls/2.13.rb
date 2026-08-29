# encoding: UTF-8

control 'C-2.13' do
  title 'Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data'
  desc  "
    User Data can be specified when launching an ec2 instance.  Examples include specifying parameters for configuring the instance or including a simple script.

    The user data is not protected by authentication or cryptographic methods.  Therefore, sensitive data, such as passwords or long-lived encryption keys should not be stored as user data.
  "
  desc  'rationale', "
    User Data can be specified when launching an ec2 instance.  Examples include specifying parameters for configuring the instance or including a simple script.

    The user data is not protected by authentication or cryptographic methods.  Therefore, sensitive data, such as passwords or long-lived encryption keys should not be stored as user data.
  "
  desc  'check', "
    From the Console:

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services` and click `EC2` under Compute.

    3. Click on `Instances`.

    4. For each instance, click `Actions` -> `Instance Settings` -> `Edit user data`

    5. For each instance, review the user data to ensure there are no secrets or sensitive data stored.

    6. If secrets or sensitive data is found, refer to the remediation below.

    7. Repeat steps 2-7 for all regions used. 

    From the Command line

    1. Run `aws ec2 describe-instances` to retrieve information about all instances in the AWS region.  The output will include instance ids.

    2. Run `aws ec2 describe-instance-attribute` for each instance in AWS account.

    ```
    aws ec2 describe-instance-attribute
    --instance-id \"ID of instance\" --attribute userData
    ```

    Note: User Data may be Base64 encoded.  Decode the output as necessary.

    3.  Review user data to ensure no secrets or sensitive information are stored.

    4.  Repeat the Audit for all the other AWS regions.
  "
  desc  'fix', "
    From the Console

    1. Login to AWS Console using `https://console.aws.amazon.com`

    2. Click `All services` and click `EC2` under Compute.

    3. Click on `Instances`.

    4. If the instance is currently running, stop the instance first.

    Note: ensure there is no negative impact from stopping the instance prior to stopping the instance. 

    5. For each instance, click `Actions` -> `Instance Settings` -> `Edit user data`

    6. For each instance, edit the user data to ensure there are no secrets or sensitive data stored.  A Secret Management solution such as AWS Secrets Manager can be used here as a more secure mechanism of storing necessary sensitive data.

    7. Repeat this remediation for all the other AWS regions.

    Note: If the ec2 instances are created via automation or infrastructure-as-code, edit the user data in those pipelines and code.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-4 a 1', 'RA-2 a', 'AC-3', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-002641', 'CCI-001045', 'CCI-000213', 'CCI-000200']
  tag cis_number:            '2.13'
  tag cis_rid:               '2.13'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-0213r1_rule'
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

  # Automated heuristic: decode each running EC2 instance's UserData
  # (base64) and scan for plaintext secret patterns — AWS access key
  # IDs (AKIA/ASIA prefixes), DB connection strings with embedded
  # passwords, and env-var-style assignments of password/api_key/token/
  # secret/access_key. Placeholder values (changeme, ${VAR}, <...>) and
  # very short values (<6 chars) are filtered out.
  #
  # Heuristic, not proof. Operators with genuine false positives
  # (intentional placeholder, encrypted blob that happens to base64-
  # decode to something pattern-matching, etc.) override via HDF
  # amendments per the `feedback_cms_attestation_pattern` memory.
  describe aws_ec2_user_data_secrets_scan do
    its('instances_with_secret_patterns') { should be_empty }
  end
end
