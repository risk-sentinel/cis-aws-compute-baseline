# Full-view ECS task definition resource — wraps `describe_task_definition`
# with `include: ['TAGS']` so controls can inspect tags (CIS 3.12) on top
# of the fields vendored `aws_ecs_task_definition` exposes.
#
# Also flattens container-definition introspection for the CIS 3.1, 3.3,
# 3.4, 3.5, 3.6, 3.7, 3.13 checks — computed arrays like
# `privileged_container_names`, `root_user_container_names`, etc., let
# control bodies stay terse.
#
# Instantiation:
#   aws_ecs_task_definition_full(task_definition: 'arn:aws:ecs:...:...')

class AwsEcsTaskDefinitionFull < AwsResourceBase
  name "aws_ecs_task_definition_full"
  desc "ECS task definition with tags + container-definition convenience methods."

  include RegionScope

  example "
    describe aws_ecs_task_definition_full(task_definition: 'sparc-api:42') do
      its('pid_mode')                 { should_not eq 'host' }
      its('privileged_container_names') { should be_empty }
    end
  "

  attr_reader :task_definition_arn, :family, :revision,
              :network_mode, :pid_mode,
              :container_names, :container_images, :container_definitions,
              :tags, :tag_keys

  def initialize(opts = {})
    opts = { task_definition: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: [:task_definition], allow: [:region])
    @display_name = opts[:task_definition]

    catch_aws_errors do
      resp = ecs_client_for(opts).describe_task_definition(
        task_definition: opts[:task_definition],
        include:         ["TAGS"],
      )
      td = resp.task_definition
      return if td.nil?

      @task_definition_arn = td.task_definition_arn
      @family              = td.family
      @revision            = td.revision
      @network_mode        = td.network_mode
      @pid_mode            = td.pid_mode
      @container_definitions = (td.container_definitions || []).map(&:to_h)

      @container_names  = @container_definitions.map { |c| c[:name] }
      @container_images = @container_definitions.map { |c| c[:image] }

      @tags     = (resp.tags || []).map { |t| { key: t.key, value: t.value } }
      @tag_keys = @tags.map { |t| t[:key] }
    end
  end

  def exists?
    !@task_definition_arn.nil?
  end

  def host_network?
    @network_mode == "host"
  end

  def privileged_container_names
    @container_definitions.select { |c| c[:privileged] == true }.map { |c| c[:name] }
  end

  def root_user_container_names
    @container_definitions.select do |c|
      u = c[:user].to_s.strip
      u == "root" || u == "0" || u.start_with?("root:") || u.start_with?("0:")
    end.map { |c| c[:name] }
  end

  def non_readonly_root_fs_container_names
    @container_definitions.reject { |c| c[:readonly_root_filesystem] == true }.map { |c| c[:name] }
  end

  def containers_missing_logging
    @container_definitions.reject do |c|
      log = c[:log_configuration]
      log && log[:log_driver] && !log[:log_driver].to_s.empty?
    end.map { |c| c[:name] }
  end

  SECRET_SHAPED_KEY_PATTERN = /password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key/i.freeze

  def containers_with_secret_shaped_env
    offenders = []
    @container_definitions.each do |c|
      env = Array(c[:environment])
      bad = env.select { |e| e[:name].to_s =~ SECRET_SHAPED_KEY_PATTERN }
      offenders.concat(bad.map { |e| "#{c[:name]}:#{e[:name]}" }) unless bad.empty?
    end
    offenders
  end

  def untrusted_image_containers(trusted_registry_prefixes)
    prefixes = Array(trusted_registry_prefixes)
    return [] if prefixes.empty?
    @container_definitions.reject do |c|
      img = c[:image].to_s
      prefixes.any? { |p| img.start_with?(p) }
    end.map { |c| "#{c[:name]}:#{c[:image]}" }
  end

  def resource_id
    @task_definition_arn || @display_name
  end

  def to_s
    "AWS ECS task definition (full) #{@display_name}"
  end
  private

  # ECS identifiers are ARNs in every path this profile uses, and an ARN names
  # its region. Without this the client stayed pinned to aws_region, so a
  # cluster in another region simply came back not-found -- indistinguishable
  # from one that does not exist.
  def ecs_client_for(opts)
    region = client_region_for(opts[:task_definition], opts[:region])
    return @aws.ecs_client if region.nil? || region.empty?
    (@clients ||= {})[region] ||= ::Aws::ECS::Client.new(region: region)
  end
end
