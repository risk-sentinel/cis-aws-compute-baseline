# Per-region enumeration of Amazon Lightsail instances + their port
# states + buckets for cis-aws-compute §5 (5.3-5.10 — 8 controls).
#
# Walk: get_instances → get_instance_port_states per instance,
# get_buckets → get_bucket_access_log_config per bucket. Each accessor
# returns the violations list for the corresponding §5.N check.
#
# Defensive `aws-sdk-lightsail` require: NOT bundled in upstream
# cinc-auditor 7.0.107. Use risksentinel/cinc-auditor extended image
# (your CI image-bake tracker) or controls fall back to attestation rationale.
#
# Per-region instantiation (consistent with other compute libraries).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsLightsailInventory < AwsResourceBase
  name "aws_lightsail_inventory"
  desc "Lightsail instances + ports + buckets (CIS §5.3-§5.10)."
  example "
    inv = aws_lightsail_inventory(allowed_ssh_cidrs: input('lightsail_allowed_ssh_cidrs'))
    if inv.connection_error
      describe inv do; skip 'attestation-required: ...'; end
    else
      describe inv do
        its('instances_with_ssh_open_to_world') { should be_empty }
      end
    end
  "

  ALL_IPV4 = "0.0.0.0/0".freeze
  ALL_IPV6 = "::/0".freeze
  WORLD_CIDRS = [ALL_IPV4, ALL_IPV6].freeze

  attr_reader :instances,
              :buckets,
              :instances_with_ssh_or_rdp_open,
              :instances_with_ssh_open_to_world,
              :instances_with_rdp_open_to_world,
              :instances_with_ipv6_enabled,
              :buckets_publicly_accessible,
              :buckets_with_iam_managed_access,
              :buckets_without_access_log,
              :buckets_without_attached_instance,
              :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    @allowed_ssh_cidrs = Array(opts.delete(:allowed_ssh_cidrs))
    @allowed_rdp_cidrs = Array(opts.delete(:allowed_rdp_cidrs))
    super(opts)
    validate_parameters
    @instances = []
    @buckets = []
    @instances_with_ssh_or_rdp_open = []
    @instances_with_ssh_open_to_world = []
    @instances_with_rdp_open_to_world = []
    @instances_with_ipv6_enabled = []
    @buckets_publicly_accessible = []
    @buckets_with_iam_managed_access = []
    @buckets_without_access_log = []
    @buckets_without_attached_instance = []
    @connection_error = nil
    begin
      require "aws-sdk-lightsail"
    rescue LoadError => e
      @connection_error = "aws-sdk-lightsail not installed: #{e.message}. Use risksentinel/cinc-auditor extended image (your CI image-bake tracker) or attest separately."
      return
    end
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "Amazon Lightsail inventory"
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
    client = ::Aws::Lightsail::Client.new(region: region)
    walk_instances(client, region)
    walk_buckets(client, region)
  rescue ::Aws::Errors::ServiceError => e
    Inspec::Log.warn("aws_lightsail_inventory: #{region} fetch failed: #{e.message}")
  end

  def walk_instances(client, region)
    page_token = nil
    loop do
      resp =
        begin
          client.get_instances(page_token: page_token)
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_lightsail_inventory: #{region} get_instances failed: #{e.message}")
          return
        end
      Array(resp.instances).each { |i| classify_instance(client, region, i) }
      break if resp.next_page_token.nil? || resp.next_page_token.empty?
      page_token = resp.next_page_token
    end
  end

  def classify_instance(client, region, instance)
    record = { region: region, name: instance.name, blueprint_id: instance.blueprint_id, state: instance.state&.name }
    @instances << record
    if instance.respond_to?(:ipv6_addresses) && Array(instance.ipv6_addresses).any?
      @instances_with_ipv6_enabled << record
    end
    ports = fetch_port_states(client, instance.name)
    return if ports.nil?
    ssh_open = port_open_to_world?(ports, 22)
    rdp_open = port_open_to_world?(ports, 3389)
    @instances_with_ssh_or_rdp_open << record if ssh_open || rdp_open
    @instances_with_ssh_open_to_world << record if ssh_open && !ssh_in_allowlist?(ports)
    @instances_with_rdp_open_to_world << record if rdp_open && !rdp_in_allowlist?(ports)
  end

  def fetch_port_states(client, instance_name)
    client.get_instance_port_states(instance_name: instance_name).port_states
  rescue ::Aws::Errors::ServiceError => e
    Inspec::Log.warn("aws_lightsail_inventory: get_instance_port_states(#{instance_name}) failed: #{e.message}")
    nil
  end

  def port_open_to_world?(port_states, port)
    Array(port_states).any? do |ps|
      ps.from_port.to_i <= port && ps.to_port.to_i >= port &&
        ps.state.to_s == "open" &&
        Array(ps.cidrs).any? { |c| WORLD_CIDRS.include?(c) }
    end
  end

  def ssh_in_allowlist?(port_states)
    return false if @allowed_ssh_cidrs.empty?
    cidrs = Array(port_states).select { |ps| ps.from_port.to_i <= 22 && ps.to_port.to_i >= 22 && ps.state.to_s == "open" }.flat_map { |ps| Array(ps.cidrs) }
    !cidrs.empty? && (cidrs - @allowed_ssh_cidrs).empty?
  end

  def rdp_in_allowlist?(port_states)
    return false if @allowed_rdp_cidrs.empty?
    cidrs = Array(port_states).select { |ps| ps.from_port.to_i <= 3389 && ps.to_port.to_i >= 3389 && ps.state.to_s == "open" }.flat_map { |ps| Array(ps.cidrs) }
    !cidrs.empty? && (cidrs - @allowed_rdp_cidrs).empty?
  end

  def walk_buckets(client, region)
    page_token = nil
    loop do
      resp =
        begin
          client.get_buckets(page_token: page_token, include_connected_resources: true)
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_lightsail_inventory: #{region} get_buckets failed: #{e.message}")
          return
        end
      Array(resp.buckets).each { |b| classify_bucket(region, b) }
      break if resp.next_page_token.nil? || resp.next_page_token.empty?
      page_token = resp.next_page_token
    end
  end

  def classify_bucket(region, bucket)
    record = { region: region, name: bucket.name, access_rules: bucket.access_rules&.to_h }
    @buckets << record
    rules = bucket.access_rules
    if rules && (rules.get_object.to_s == "public" || rules.allow_public_overrides)
      @buckets_publicly_accessible << record
    end
    unless bucket.respond_to?(:access_log_config) && bucket.access_log_config && bucket.access_log_config.enabled
      @buckets_without_access_log << record
    end
    if Array(bucket.resources_receiving_access).empty?
      @buckets_without_attached_instance << record
    end
    if rules && rules.get_object.to_s == "private" && Array(bucket.readonly_access_accounts).empty? && bucket.respond_to?(:tags) && Array(bucket.tags).none? { |t| t.key == "lightsail-iam-managed" }
      @buckets_with_iam_managed_access << record
    end
  end
end
