# Per-region enumeration of ECS task sets and their assignPublicIp
# setting. For cis-aws-compute C-3.14 (Ensure assignPublicIp is set to
# DISABLED for Amazon ECS task sets).
#
# Walk: list_clusters → list_services per cluster → describe_task_sets
# per (cluster, service). Task sets with `network_configuration.
# awsvpc_configuration.assign_public_ip != "DISABLED"` go to the
# offender list.
#
# Per-region instantiation (consistent with other compute libraries).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsEcsTaskSets < AwsResourceBase
  name "aws_ecs_task_sets"
  desc "ECS task sets with assignPublicIp != DISABLED (CIS 3.14)."

  include RegionScope
  example "
    describe aws_ecs_task_sets do
      its('task_sets_with_public_ip') { should be_empty }
    end
  "

  attr_reader :task_sets_with_public_ip, :task_sets_total

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @task_sets_with_public_ip = []
    @task_sets_total = 0
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "ECS task sets with public IP assignment"
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
    client = ::Aws::ECS::Client.new(region: region)
    list_clusters(client, region).each do |cluster_arn|
      list_services(client, region, cluster_arn).each_slice(10) do |services|
        next if services.empty?
        check_task_sets(client, region, cluster_arn, services)
      end
    end
  end

  def list_clusters(client, region)
    arns = []
    next_token = nil
    loop do
      resp =
        begin
          client.list_clusters(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          (@region_errors ||= {})[region] = "aws_ecs_task_sets: #{region} list_clusters failed: #{e.message}"
          Inspec::Log.warn("aws_ecs_task_sets: #{region} list_clusters failed: #{e.message}")
          return arns
        end
      arns.concat(Array(resp.cluster_arns))
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    arns
  end

  def list_services(client, region, cluster_arn)
    arns = []
    next_token = nil
    loop do
      resp =
        begin
          client.list_services(cluster: cluster_arn, next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          (@region_errors ||= {})[region] = "aws_ecs_task_sets: #{region} list_services(#{cluster_arn}) failed: #{e.message}"
          Inspec::Log.warn("aws_ecs_task_sets: #{region} list_services(#{cluster_arn}) failed: #{e.message}")
          return arns
        end
      arns.concat(Array(resp.service_arns))
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    arns
  end

  def check_task_sets(client, region, cluster_arn, service_arns)
    desc =
      begin
        client.describe_services(cluster: cluster_arn, services: service_arns)
      rescue ::Aws::Errors::ServiceError => e
        (@region_errors ||= {})[region] = "aws_ecs_task_sets: #{region} describe_services failed: #{e.message}"
        Inspec::Log.warn("aws_ecs_task_sets: #{region} describe_services failed: #{e.message}")
        return
      end
    Array(desc.services).each do |svc|
      Array(svc.task_sets).each do |ts|
        @task_sets_total += 1
        cfg = ts.network_configuration&.awsvpc_configuration
        next if cfg.nil?
        assign = cfg.assign_public_ip.to_s
        next if assign == "DISABLED"
        @task_sets_with_public_ip << {
          region:                region,
          cluster_arn:           cluster_arn,
          service_arn:           svc.service_arn,
          task_set_arn:          ts.task_set_arn,
          assign_public_ip:      assign,
        }
      end
    end
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
