# Per-region enumeration of Elastic Beanstalk environments + their
# configuration settings, joined into a single composite resource for
# cis-aws-compute §10 (10.1 / 10.2 / 10.3 / 10.4).
#
# Walk: describe_environments → describe_configuration_settings per
# environment. Configuration settings are namespaced (e.g.,
# `aws:elasticbeanstalk:managedactions` for managed updates,
# `aws:elasticbeanstalk:hostmanager` for persistent logs,
# `aws:elasticbeanstalk:environment:loadbalancer:application` for
# access-log + HTTPS settings).
#
# Each accessor returns the violations list — environments that fail
# the specific §10.N check.
#
# Per-region instantiation. aws-sdk-elasticbeanstalk IS bundled in
# stock cinc-auditor (verified 2026-05-06).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsElasticBeanstalkEnvironments < AwsResourceBase
  name "aws_elastic_beanstalk_environments"
  desc "Elastic Beanstalk environments + configuration violations (CIS §10)."

  include RegionScope
  example "
    describe aws_elastic_beanstalk_environments do
      its('environments_without_managed_updates') { should be_empty }
      its('environments_without_persistent_logs') { should be_empty }
      its('environments_without_access_logs')    { should be_empty }
      its('environments_without_https')           { should be_empty }
    end
  "

  attr_reader :environments,
              :environments_without_managed_updates,
              :environments_without_persistent_logs,
              :environments_without_access_logs,
              :environments_without_https

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @environments = []
    @environments_without_managed_updates = []
    @environments_without_persistent_logs = []
    @environments_without_access_logs = []
    @environments_without_https = []
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "Elastic Beanstalk environments"
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
    # Bundled in the auditor image is not the same as loaded: without this the
    # first call raises `uninitialized constant Aws::ElasticBeanstalk`, which
    # `check` and `json` never see because they do not run control bodies.
    require 'aws-sdk-elasticbeanstalk' unless defined?(::Aws::ElasticBeanstalk::Client)
    client = ::Aws::ElasticBeanstalk::Client.new(region: region)
    list_environments(client, region).each do |env|
      classify(client, region, env)
    end
  end

  def list_environments(client, region)
    rows = []
    next_token = nil
    loop do
      resp =
        begin
          client.describe_environments(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          (@region_errors ||= {})[region] = "aws_elastic_beanstalk_environments: #{region} describe_environments failed: #{e.message}"
          Inspec::Log.warn("aws_elastic_beanstalk_environments: #{region} describe_environments failed: #{e.message}")
          return rows
        end
      Array(resp.environments).each do |e|
        next if e.status == "Terminated"
        rows << { region: region, name: e.environment_name, application: e.application_name }
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    rows
  end

  def classify(client, region, env)
    @environments << env
    settings = fetch_settings(client, env)
    return if settings.nil?
    options = settings.flat_map { |s| Array(s.option_settings) }
    @environments_without_managed_updates << env unless managed_updates_enabled?(options)
    @environments_without_persistent_logs << env unless persistent_logs_enabled?(options)
    @environments_without_access_logs    << env unless access_logs_enabled?(options)
    @environments_without_https          << env unless https_enabled?(options)
  end

  def fetch_settings(client, env)
    client.describe_configuration_settings(
      application_name: env[:application],
      environment_name: env[:name],
    ).configuration_settings
  rescue ::Aws::Errors::ServiceError => e
    Inspec::Log.warn("aws_elastic_beanstalk_environments: describe_configuration_settings(#{env[:application]}/#{env[:name]}) failed: #{e.message}")
    nil
  end

  def option_value(options, namespace, name)
    opt = options.find { |o| o.namespace == namespace && o.option_name == name }
    opt&.value
  end

  def managed_updates_enabled?(options)
    val = option_value(options, "aws:elasticbeanstalk:managedactions", "ManagedActionsEnabled")
    val.to_s.casecmp("true").zero?
  end

  def persistent_logs_enabled?(options)
    val = option_value(options, "aws:elasticbeanstalk:hostmanager", "LogPublicationControl")
    val.to_s.casecmp("true").zero?
  end

  def access_logs_enabled?(options)
    val = option_value(options, "aws:elasticbeanstalk:environment:loadbalancer:application", "ConnectionDrainingEnabled") &&
          option_value(options, "aws:elbv2:loadbalancer", "AccessLogsS3Enabled")
    val.to_s.casecmp("true").zero?
  end

  def https_enabled?(options)
    protocol = option_value(options, "aws:elbv2:listener:443", "Protocol") ||
               option_value(options, "aws:elb:listener:443", "InstanceProtocol")
    protocol.to_s.casecmp("https").zero?
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
