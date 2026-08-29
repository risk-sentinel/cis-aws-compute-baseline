# ECS inventory helper — returns flat iterables suited for control
# describes:
#
#   aws_ecs_inventory.cluster_arns
#     => [<cluster-arn>, ...]
#
#   aws_ecs_inventory.service_keys
#     => [{cluster: <cluster-arn>, service: <service-arn>}, ...]
#
#   aws_ecs_inventory.latest_active_task_definition_arns
#     => [<arn>, ...]  # one per family, highest revision, status=ACTIVE
#
# Why not vendored `aws_ecs_task_definitions`: it lists every revision
# of every family, which inflates iteration cost and flags old revisions
# that are no longer deployable. CIS intent is "latest active revision",
# which is what this helper returns.

class AwsEcsInventory < AwsResourceBase
  name "aws_ecs_inventory"
  desc "ECS inventory: clusters, services, latest-ACTIVE task definitions."

  example "
    describe aws_ecs_inventory do
      its('cluster_arns') { should_not be_empty }
    end
  "

  include RegionScope

  attr_reader :cluster_arns, :regions, :region_errors, :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @regions, scope_error = resolve_region_scope(@aws, region_override)
    @cluster_arns, @region_errors = fetch_cluster_arns
    @connection_error = scope_error || region_error_summary(@region_errors, @regions.size)
  end

  # ARNs carry their own region, so downstream calls are routed by parsing it
  # back out rather than by threading a region through every method.
  def ecs_for(region)
    (@clients ||= {})[region] ||= ::Aws::ECS::Client.new(region: region)
  end

  def region_of(arn)
    arn.to_s.split(':')[3]
  end

  def fetch_cluster_arns
    each_region_collecting(@regions) do |region|
      client = ecs_for(region)
      arns = []
      token = nil
      loop do
        args = {}
        args[:next_token] = token if token
        resp = client.list_clusters(args)
        arns.concat(resp.cluster_arns)
        token = resp.next_token
        break unless token
      end
      arns
    end
  end

  def service_keys
    @service_keys ||= @cluster_arns.flat_map do |cluster_arn|
      client = ecs_for(region_of(cluster_arn))
      arns = []
      token = nil
      begin
        loop do
          args = { cluster: cluster_arn }
          args[:next_token] = token if token
          resp = client.list_services(args)
          arns.concat(resp.service_arns)
          token = resp.next_token
          break unless token
        end
      rescue ::Aws::Errors::ServiceError => e
        (@region_errors ||= {})[region_of(cluster_arn)] = "list_services: #{e.message}"
      end
      arns.map { |s| { cluster: cluster_arn, service: s } }
    end
  end

  def latest_active_task_definition_arns
    @latest_active_task_definition_arns ||= begin
      rows, errs = each_region_collecting(@regions) do |region|
        client = ecs_for(region)
        families = []
        token = nil
        loop do
          args = { status: "ACTIVE" }
          args[:next_token] = token if token
          resp = client.list_task_definition_families(args)
          families.concat(resp.families)
          token = resp.next_token
          break unless token
        end
        families.map do |family|
          client.list_task_definitions(
            family_prefix: family,
            status:        "ACTIVE",
            sort:          "DESC",
            max_results:   1,
          ).task_definition_arns.first
        end.compact
      end
      (@region_errors ||= {}).merge!(errs)
      rows
    end
  end

  def to_s
    "AWS ECS inventory (clusters=#{@cluster_arns.size}, regions: #{@regions.join(', ')})"
  end
end
