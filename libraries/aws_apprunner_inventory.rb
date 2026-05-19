# Per-region enumeration of AWS App Runner services + their VPC
# connector configuration for cis-aws-compute C-6.1 (Ensure VPC
# Endpoints for source code access).
#
# App Runner pulls source from CodeCommit / GitHub via either a public
# endpoint or a VPC connector. This control verifies the VPC connector
# is in use AND there's a corresponding `com.amazonaws.<region>.codecommit`
# (or codestar-connections) interface endpoint in the VPC.
#
# Defensive `aws-sdk-apprunner` require: NOT bundled in upstream
# cinc-auditor 7.0.107. Use risksentinel/cinc-auditor extended image
# (your CI image-bake tracker) or controls fall back to attestation rationale.
#
# Per-region instantiation (consistent with other compute libraries).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsAppRunnerInventory < AwsResourceBase
  name "aws_apprunner_inventory"
  desc "App Runner services + VPC connector source-code coverage (CIS 6.1)."
  example "
    inv = aws_apprunner_inventory
    if inv.connection_error
      describe inv do; skip 'attestation-required: ...'; end
    else
      describe inv do
        its('services_without_vpc_connector') { should be_empty }
      end
    end
  "

  attr_reader :services, :services_without_vpc_connector, :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @services = []
    @services_without_vpc_connector = []
    @connection_error = nil
    begin
      require "aws-sdk-apprunner"
    rescue LoadError => e
      @connection_error = "aws-sdk-apprunner not installed: #{e.message}. Use risksentinel/cinc-auditor extended image (your CI image-bake tracker) or attest separately."
      return
    end
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "AWS App Runner inventory"
  end

  private

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
    client = ::Aws::AppRunner::Client.new(region: region)
    next_token = nil
    loop do
      resp =
        begin
          client.list_services(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_apprunner_inventory: #{region} list_services failed: #{e.message}")
          return
        end
      Array(resp.service_summary_list).each do |svc|
        check_service(client, region, svc)
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
  end

  def check_service(client, region, summary)
    record = { region: region, service_arn: summary.service_arn, service_name: summary.service_name }
    @services << record
    detail =
      begin
        client.describe_service(service_arn: summary.service_arn).service
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_apprunner_inventory: describe_service(#{summary.service_arn}) failed: #{e.message}")
        @services_without_vpc_connector << record
        return
      end
    network_cfg = detail&.network_configuration
    egress_type = network_cfg&.egress_configuration&.egress_type
    return if egress_type.to_s == "VPC"
    @services_without_vpc_connector << record
  end
end
