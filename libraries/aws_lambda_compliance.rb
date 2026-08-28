# Per-region Lambda function compliance checks for cis-aws-compute §12
# (Lambda controls). Specifically:
#
# - C-12.4 Least Privilege — flag functions whose execution role has
#   AdministratorAccess (or any FullAccess managed policy) attached.
# - C-12.9 Admin Privileges — same accessor as C-12.4 (CIS phrases the
#   same concern from a different angle).
# - C-12.10 Cross-Account Access — `get_policy` per function; flag
#   resource policies allowing non-self-account principals or `*`.
# - C-12.11 Runtime EOL — flag functions whose `runtime` is not in
#   the `lambda_runtime_allowlist` input (when populated).
#
# Per-region instantiation. aws-sdk-lambda + aws-sdk-iam IS bundled in
# stock cinc-auditor.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

require "json"
require "set"

class AwsLambdaCompliance < AwsResourceBase
  name "aws_lambda_compliance"
  desc "Lambda compliance accessors (CIS §12.4 / §12.9 / §12.10 / §12.11)."

  include RegionScope
  example "
    inv = aws_lambda_compliance(runtime_allowlist: input('lambda_runtime_allowlist'))
    describe inv do
      its('functions_with_admin_policy')             { should be_empty }
      its('functions_with_cross_account_principals') { should be_empty }
      its('functions_with_eol_runtime')              { should be_empty }
    end
  "

  ADMIN_POLICY_ARN_RE = %r{
    arn:aws[^:]*:iam::aws:policy/
    (AdministratorAccess|.*FullAccess)$
  }x.freeze

  attr_reader :functions,
              :functions_with_admin_policy,
              :functions_with_cross_account_principals,
              :functions_with_eol_runtime

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    @runtime_allowlist = Array(opts.delete(:runtime_allowlist)).map(&:to_s)
    super(opts)
    validate_parameters
    @functions = []
    @functions_with_admin_policy = []
    @functions_with_cross_account_principals = []
    @functions_with_eol_runtime = []
    @account_id = fetch_account_id
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "Lambda compliance"
  end

  private

  def fetch_account_id
    sts = ::Aws::STS::Client.new
    sts.get_caller_identity.account
  rescue ::Aws::Errors::ServiceError
    nil
  end

  def fetch_default_regions
    regions = []
    catch_aws_errors do
      regions = @aws.compute_client.describe_regions.regions.map(&:region_name)
    end
    regions
  end

  def fetch_data
    @regions.each { |r| walk_region(r) }
  end

  def walk_region(region)
    lambda_client = ::Aws::Lambda::Client.new(region: region)
    iam = ::Aws::IAM::Client.new(region: region)
    next_marker = nil
    loop do
      resp =
        begin
          lambda_client.list_functions(marker: next_marker)
        rescue ::Aws::Errors::ServiceError => e
          (@region_errors ||= {})[region] = "aws_lambda_compliance: #{region} list_functions failed: #{e.message}"
          Inspec::Log.warn("aws_lambda_compliance: #{region} list_functions failed: #{e.message}")
          return
        end
      Array(resp.functions).each { |f| classify_function(lambda_client, iam, region, f) }
      break if resp.next_marker.nil? || resp.next_marker.empty?
      next_marker = resp.next_marker
    end
  end

  def classify_function(lambda_client, iam, region, function)
    record = {
      region:        region,
      function_name: function.function_name,
      function_arn:  function.function_arn,
      runtime:       function.runtime,
      role:          function.role,
    }
    @functions << record

    classify_role(iam, record)
    classify_resource_policy(lambda_client, record)
    classify_runtime(record)
  end

  def classify_role(iam, record)
    role_name = record[:role].to_s.split("/").last
    return if role_name.empty?
    attached =
      begin
        iam.list_attached_role_policies(role_name: role_name).attached_policies
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_lambda_compliance: list_attached_role_policies(#{role_name}) failed: #{e.message}")
        return
      end
    Array(attached).each do |p|
      next unless ADMIN_POLICY_ARN_RE.match?(p.policy_arn.to_s)
      @functions_with_admin_policy << record.merge(policy_arn: p.policy_arn)
      break
    end
  end

  def classify_resource_policy(lambda_client, record)
    policy_str =
      begin
        lambda_client.get_policy(function_name: record[:function_arn]).policy
      rescue ::Aws::Lambda::Errors::ResourceNotFoundException
        return
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_lambda_compliance: get_policy(#{record[:function_name]}) failed: #{e.message}")
        return
      end
    doc = JSON.parse(policy_str.to_s)
    Array(doc["Statement"]).each do |s|
      next unless s["Effect"] == "Allow"
      principals = extract_principal_accounts(s["Principal"])
      cross = principals.any? { |a| a == "*" || (a != @account_id && !a.nil?) }
      next unless cross
      @functions_with_cross_account_principals << record.merge(sid: s["Sid"], principals: principals.to_a)
      break
    end
  rescue JSON::ParserError
    nil
  end

  def extract_principal_accounts(principal)
    accounts = Set.new
    return Set[principal.to_s] if principal.is_a?(String)
    return accounts unless principal.is_a?(Hash)
    %w[AWS Service Federated CanonicalUser].each do |k|
      Array(principal[k]).each do |v|
        s = v.to_s
        if s == "*"
          accounts << "*"
        elsif s.start_with?("arn:")
          # Extract account ID from ARN.
          parts = s.split(":")
          accounts << parts[4] if parts.length > 4
        else
          accounts << s
        end
      end
    end
    accounts
  end

  def classify_runtime(record)
    return if @runtime_allowlist.empty?
    return if @runtime_allowlist.include?(record[:runtime].to_s)
    @functions_with_eol_runtime << record
  end

  # Regions that could not be read, keyed by region. A region that errors
  # contributes no rows, so without this an inaccessible region is
  # indistinguishable from an empty one and the control passes.
  def region_errors
    @region_errors ||= {}
  end

  # Falls back to whatever the resource already recorded (a missing SDK gem, a
  # failed bootstrap) and only then to region failures, so neither hides the
  # other. A `def` here overrides any attr_reader of the same name, which is how
  # the first attempt at this silently dropped the gem-missing message.
  def connection_error
    @connection_error || region_error_summary(region_errors, Array(@regions).size)
  end
end
