# Full-view ECS service resource — wraps `describe_services` with
# `include: ['TAGS']` so controls can inspect:
#
#   - launch_type + platform_version (CIS 3.8)
#   - assign_public_ip from network_configuration.awsvpc_configuration (CIS 3.2)
#   - tag_keys (CIS 3.10)
#
# Instantiation:
#   aws_ecs_service_full(cluster: 'prod', service: 'api')

class AwsEcsServiceFull < AwsResourceBase
  name "aws_ecs_service_full"
  desc "ECS service with tags and network-config fields exposed."

  example "
    describe aws_ecs_service_full(cluster: 'prod-sparc', service: 'api') do
      its('platform_version') { should eq 'LATEST' }
      its('assign_public_ip') { should eq 'DISABLED' }
    end
  "

  attr_reader :service_arn, :service_name, :cluster_arn,
              :launch_type, :platform_version, :assign_public_ip,
              :tags, :tag_keys

  def initialize(opts = {})
    super(opts)
    validate_parameters(required: %i[cluster service])
    @display_name = opts[:service]

    catch_aws_errors do
      resp = @aws.ecs_client.describe_services(
        cluster:  opts[:cluster],
        services: [opts[:service]],
        include:  ["TAGS"],
      )
      s = resp.services.first
      return if s.nil?

      @service_arn      = s.service_arn
      @service_name     = s.service_name
      @cluster_arn      = s.cluster_arn
      @launch_type      = s.launch_type
      @platform_version = s.platform_version

      awsvpc = s.network_configuration&.awsvpc_configuration
      @assign_public_ip = awsvpc&.assign_public_ip

      @tags     = (s.tags || []).map { |t| { key: t.key, value: t.value } }
      @tag_keys = @tags.map { |t| t[:key] }
    end
  end

  def exists?
    !@service_arn.nil?
  end

  def fargate?
    @launch_type == "FARGATE"
  end

  def resource_id
    @service_arn || @display_name
  end

  def to_s
    "AWS ECS service (full) #{@display_name}"
  end
end
