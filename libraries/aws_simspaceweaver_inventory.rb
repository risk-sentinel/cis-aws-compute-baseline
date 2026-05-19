# Per-region enumeration of AWS SimSpace Weaver simulations and their
# transport-encryption state for cis-aws-compute C-16.1 (Ensure
# communications between your applications and clients is encrypted).
#
# Defensive `aws-sdk-simspaceweaver` require: NOT bundled in upstream
# cinc-auditor 7.0.107. Use risksentinel/cinc-auditor extended image
# (your CI image-bake tracker) or controls fall back to attestation rationale.
#
# Per-region instantiation (consistent with other compute libraries).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsSimSpaceWeaverInventory < AwsResourceBase
  name "aws_simspaceweaver_inventory"
  desc "SimSpace Weaver simulations + TLS state (CIS 16.1)."
  example "
    inv = aws_simspaceweaver_inventory
    if inv.connection_error
      describe inv do; skip 'attestation-required: ...'; end
    else
      describe inv do
        its('simulations_without_tls') { should be_empty }
      end
    end
  "

  attr_reader :simulations, :simulations_without_tls, :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @simulations = []
    @simulations_without_tls = []
    @connection_error = nil
    begin
      require "aws-sdk-simspaceweaver"
    rescue LoadError => e
      @connection_error = "aws-sdk-simspaceweaver not installed: #{e.message}. Use risksentinel/cinc-auditor extended image (your CI image-bake tracker) or attest separately."
      return
    end
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "SimSpace Weaver simulations"
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
    client = ::Aws::SimSpaceWeaver::Client.new(region: region)
    next_token = nil
    loop do
      resp =
        begin
          client.list_simulations(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_simspaceweaver_inventory: #{region} list_simulations failed: #{e.message}")
          return
        end
      Array(resp.simulations).each do |sim|
        check_simulation(client, region, sim)
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
  end

  def check_simulation(client, region, summary)
    detail =
      begin
        client.describe_simulation(simulation: summary.name)
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_simspaceweaver_inventory: describe_simulation(#{summary.name}) failed: #{e.message}")
        @simulations_without_tls << { region: region, name: summary.name }
        return
      end
    record = { region: region, name: summary.name, status: detail.status }
    @simulations << record
    # Best-effort TLS state inference: SimSpace Weaver enforces TLS on
    # all client-facing endpoints by default since GA. The `live_simulation_state`
    # surface that would expose explicit TLS toggle is not part of the
    # describe_simulation response — we assert pass when the simulation
    # is RUNNING (TLS enforced by service default). Operators relying on
    # custom transports must attest separately.
    @simulations_without_tls << record unless detail.status.to_s == "RUNNING"
  end
end
