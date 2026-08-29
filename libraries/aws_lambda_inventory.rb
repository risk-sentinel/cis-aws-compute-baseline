# Lambda inventory helper — one-shot list_functions paginated, plus
# offender-list helpers that the section 12 controls compose.
#
# Exposed iterables:
#   aws_lambda_inventory.function_names
#   aws_lambda_inventory.function_arns
#
# Offender lists (each is an array of strings; empty == passing):
#   .functions_missing_lambda_insights              (CIS 12.2)
#   .role_duplicate_offenders                       (CIS 12.5)
#   .functions_missing_dlq                          (the consumer stricter; CIS 12.5)
#   .public_function_names                          (CIS 12.6)
#   .functions_not_vpc_attached                     (the consumer stricter; CIS 12.6)
#   .role_invalid_function_names                    (CIS 12.7)
#   .functions_without_code_signing                 (CIS 12.8)
#   .functions_runtime_outside_allowlist(allowlist) (CIS 12.11)
#   .functions_missing_env_kms                      (CIS 12.12)

class AwsLambdaInventory < AwsResourceBase
  name "aws_lambda_inventory"
  desc "Lambda inventory: function configurations + offender helpers."

  example "
    describe aws_lambda_inventory do
      its('function_names') { should_not be_empty }
    end
  "

  attr_reader :functions

  include RegionScope

  attr_reader :regions, :region_errors, :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @regions, scope_error = resolve_region_scope(@aws, region_override)
    @functions, @region_errors = fetch_functions
    @connection_error = scope_error || region_error_summary(@region_errors, @regions.size)
  end

  # Per-function calls below must reach the region the function lives in, so
  # each row carries its region and the client is selected from it.
  def lambda_for(region)
    (@clients ||= {})[region] ||= ::Aws::Lambda::Client.new(region: region)
  end

  def fetch_functions
    each_region_collecting(@regions) do |region|
      client = lambda_for(region)
      fns = []
      marker = nil
      loop do
        args = {}
        args[:marker] = marker if marker
        resp = client.list_functions(args)
        fns.concat(resp.functions.map { |f| f.to_h.merge(region: region) })
        marker = resp.next_marker
        break unless marker
      end
      fns
    end
  end

  def function_names
    @functions.map { |f| f[:function_name] }
  end

  def function_arns
    @functions.map { |f| f[:function_arn] }
  end

  def functions_missing_lambda_insights
    @functions.reject do |f|
      Array(f[:layers]).any? { |l| l[:arn].to_s.include?("LambdaInsightsExtension") }
    end.map { |f| f[:function_name] }
  end

  def role_duplicate_offenders
    grouped = @functions.group_by { |f| f[:role] }
    grouped.select { |role, fs| !role.to_s.empty? && fs.size > 1 }.flat_map do |role, fs|
      fs.map { |f| "#{f[:function_name]}:role=#{role}" }
    end
  end

  def functions_missing_dlq
    @functions.reject do |f|
      target = f.dig(:dead_letter_config, :target_arn).to_s
      !target.empty?
    end.map { |f| f[:function_name] }
  end

  def functions_not_vpc_attached
    @functions.reject do |f|
      vpc_id = f.dig(:vpc_config, :vpc_id).to_s
      !vpc_id.empty?
    end.map { |f| f[:function_name] }
  end

  def functions_missing_env_kms
    @functions.select do |f|
      vars = f.dig(:environment, :variables) || {}
      !vars.empty?
    end.reject do |f|
      key = f[:kms_key_arn].to_s
      !key.empty?
    end.map { |f| f[:function_name] }
  end

  def functions_runtime_outside_allowlist(allowlist)
    al = Array(allowlist)
    return [] if al.empty?
    @functions.reject { |f| al.include?(f[:runtime].to_s) }
              .map { |f| "#{f[:function_name]}:runtime=#{f[:runtime]}" }
  end

  def public_function_names
    require "json"
    @functions.each_with_object([]) do |f, acc|
      policy_str = nil
      catch_aws_errors do
        resp = lambda_for(f[:region]).get_policy(function_name: f[:function_name])
        policy_str = resp.policy
      end
      next unless policy_str

      begin
        policy = JSON.parse(policy_str)
      rescue JSON::ParserError
        next
      end

      Array(policy["Statement"]).each do |stmt|
        next unless stmt["Effect"] == "Allow"
        principal = stmt["Principal"]
        if principal == "*" ||
           (principal.is_a?(Hash) && (principal["AWS"] == "*" || Array(principal["AWS"]).include?("*")))
          acc << f[:function_name]
          break
        end
      end
    end
  end

  def functions_without_code_signing
    @functions.reject do |f|
      arn = nil
      catch_aws_errors do
        resp = lambda_for(f[:region]).get_function_code_signing_config(function_name: f[:function_name])
        arn = resp.code_signing_config_arn
      end
      !arn.to_s.empty?
    end.map { |f| f[:function_name] }
  end

  def role_invalid_function_names
    iam = @aws.iam_client
    @functions.each_with_object([]) do |f, acc|
      role_arn = f[:role].to_s
      next if role_arn.empty?
      role_name = role_arn.split("/").last
      role_exists = false
      catch_aws_errors do
        iam.get_role(role_name: role_name)
        role_exists = true
      end
      acc << "#{f[:function_name]}:role=#{role_arn}" unless role_exists
    end
  end

  def to_s
    "AWS Lambda inventory (functions=#{@functions.size})"
  end
end
