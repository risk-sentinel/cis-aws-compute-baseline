# Per-region enumeration of EC2 instances that have been in the
# `stopped` state for more than N days. For cis-aws-compute C-2.11
# (Ensure instances stopped for over 90 days are removed).
#
# `describe_instances` doesn't return a structured state-transition
# timestamp, but `state_transition_reason` is a human-readable string
# whose tail contains a parenthesized timestamp for state-changing
# events ("User initiated (2025-09-15 14:30:00 GMT)"). We parse that
# string to compute days-stopped. When the format doesn't match the
# expected shape (custom termination via spot-fleet, autoscaling-driven
# stops, etc.), the instance is excluded from the violations list with
# a warning rather than failing closed — the consumer attests via the
# documented runbook for the unmatched cases.
#
# Threshold is configurable via the `stopped_instance_max_age_days` input
# (default 90 per CIS).
#
# Per-region instantiation (consistent with other compute libraries).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsEc2LongStoppedInstances < AwsResourceBase
  name "aws_ec2_long_stopped_instances"
  desc "EC2 instances stopped longer than N days (CIS 2.11)."

  include RegionScope
  example "
    inv = aws_ec2_long_stopped_instances(threshold_days: 90)
    describe inv do
      its('long_stopped_instances') { should be_empty }
    end
  "

  TIMESTAMP_RE = /\(([\d\-:\s]+(?:GMT|UTC))\)/.freeze

  attr_reader :long_stopped_instances, :unparseable_reasons, :threshold_days

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    @threshold_days = (opts.delete(:threshold_days) || 90).to_i
    super(opts)
    validate_parameters
    @long_stopped_instances = []
    @unparseable_reasons = []
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "EC2 long-stopped instances (>#{@threshold_days}d)"
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
    threshold = Time.now - (@threshold_days * 24 * 60 * 60)
    @regions.each do |region|
      walk_region(region, threshold)
    end
  end

  def walk_region(region, threshold)
    client = ::Aws::EC2::Client.new(region: region)
    next_token = nil
    loop do
      resp =
        begin
          client.describe_instances(
            filters: [{ name: "instance-state-name", values: ["stopped"] }],
            next_token: next_token,
          )
        rescue ::Aws::Errors::ServiceError => e
          (@region_errors ||= {})[region] = "aws_ec2_long_stopped_instances: #{region} describe_instances failed: #{e.message}"
          Inspec::Log.warn("aws_ec2_long_stopped_instances: #{region} describe_instances failed: #{e.message}")
          return
        end
      Array(resp.reservations).each do |r|
        Array(r.instances).each { |i| classify(region, i, threshold) }
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
  end

  def classify(region, instance, threshold)
    reason = instance.state_transition_reason.to_s
    match = reason.match(TIMESTAMP_RE)
    if match.nil?
      @unparseable_reasons << { region: region, instance_id: instance.instance_id, reason: reason }
      return
    end
    stopped_at =
      begin
        Time.parse(match[1])
      rescue ArgumentError
        @unparseable_reasons << { region: region, instance_id: instance.instance_id, reason: reason }
        return
      end
    return if stopped_at > threshold
    @long_stopped_instances << {
      region:      region,
      instance_id: instance.instance_id,
      stopped_at:  stopped_at.iso8601,
      days:        ((Time.now - stopped_at) / 86_400).to_i,
    }
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
