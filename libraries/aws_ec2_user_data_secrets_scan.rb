# Scan every running EC2 instance's UserData for plaintext secret
# patterns (CIS AWS Compute 2.13). EC2 user_data lives in a separate
# instance-attribute call (DescribeInstanceAttribute with Attribute:
# userData) rather than in DescribeInstances — needs a per-instance
# round-trip.
#
# The scan is heuristic, not proof. Patterns prioritized for low
# false-positive rate in the cloud-init use case:
#
#   - AWS access keys (AKIA / ASIA prefixes — high specificity)
#   - DB password in connection-string form (postgres://x:PWD@host)
#   - Generic password / token / secret env-var assignments (env var
#     name in a denylist + non-empty value that isn't a placeholder)
#
# Operators with genuine false positives (e.g., a placeholder string
# that happens to match) override via HDF amendments per the
# `feedback_cms_attestation_pattern` memory; the resource doesn't try
# to be exhaustive.
#
# Depends on `_aws_backend_bootstrap.rb` having been loaded first.

class AwsEc2UserDataSecretsScan < AwsResourceBase
  name "aws_ec2_user_data_secrets_scan"
  desc "Scan EC2 user_data for plaintext secret patterns (CIS 2.13)."
  example "
    describe aws_ec2_user_data_secrets_scan do
      its('instances_with_secret_patterns') { should be_empty }
    end
  "

  AWS_ACCESS_KEY_RE = /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b/.freeze

  PASSWORD_URL_RE   = %r{(?:postgres|postgresql|mysql|mariadb|mongodb|redis)://[^:@/\s]+:([^@\s]+)@}i.freeze

  ENV_ASSIGN_RE     = /\b(?:password|passwd|api[_-]?key|secret|token|access[_-]?key)\b\s*[:=]\s*["']?([^\s"'#{Regexp.escape('${')}][^\s"']+)/i.freeze

  PLACEHOLDER_RE    = /\A(?:changeme|placeholder|example|todo|fixme|xxx+|\*+|\.\.\.|<.*>|\$\{.*\})\z/i.freeze

  attr_reader :instances_with_secret_patterns, :connection_error

  def initialize(opts = {})
    super(opts)
    validate_parameters
    @instances_with_secret_patterns = []
    @connection_error = nil
    fetch_data
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "EC2 UserData secret-pattern scan"
  end

  private

  def fetch_data
    instance_ids = []
    begin
      paginate_describe_instances do |resp|
        Array(resp.reservations).each do |r|
          Array(r.instances).each do |i|
            instance_ids << i.instance_id if i.state && i.state.name == "running"
          end
        end
      end
    rescue ::Aws::Errors::ServiceError => e
      @connection_error = "describe_instances failed: #{e.class.name}: #{e.message}"
      return
    end

    instance_ids.each do |id|
      scan_instance(id)
    end
  end

  def paginate_describe_instances
    token = nil
    loop do
      args = {}
      args[:next_token] = token if token
      resp = @aws.compute_client.describe_instances(args)
      yield(resp)
      token = resp.next_token
      break unless token && !token.empty?
    end
  end

  def scan_instance(instance_id)
    raw = nil
    begin
      resp = @aws.compute_client.describe_instance_attribute(
        instance_id: instance_id,
        attribute:   "userData",
      )
      raw = resp.user_data && resp.user_data.value
    rescue ::Aws::Errors::ServiceError => e
      @instances_with_secret_patterns << "#{instance_id}: describe_instance_attribute failed (#{e.class.name})"
      return
    end
    return if raw.nil? || raw.empty?

    decoded =
      begin
        require 'base64'
        Base64.strict_decode64(raw)
      rescue StandardError
        # If decode fails, treat the raw value as plaintext.
        raw
      end

    findings = []

    findings << "AWS access key id" if decoded.match?(AWS_ACCESS_KEY_RE)

    decoded.scan(PASSWORD_URL_RE).each do |m|
      pwd = m[0].to_s
      next if pwd.match?(PLACEHOLDER_RE)
      findings << "DB connection string with embedded password"
      break
    end

    decoded.scan(ENV_ASSIGN_RE).each do |m|
      val = m[0].to_s
      next if val.match?(PLACEHOLDER_RE)
      next if val.length < 6 # too short to be a real secret
      findings << "Env-style secret assignment (password/api_key/token/secret/access_key)"
      break
    end

    @instances_with_secret_patterns << "#{instance_id}: #{findings.join('; ')}" unless findings.empty?
  end
end
