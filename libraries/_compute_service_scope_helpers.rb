# Auto-detect compute services in use + apply consumer overrides.
#
# Provides one method to control bodies:
#
#   compute_service_in_scope?('lambda')   # => true / false
#
# Semantics (in order):
#
#   1. If service is in `excluded_services` input → out of scope (consumer
#      explicitly suppressed it). Excluded trumps everything else.
#   2. If service is in `forced_services` input → in scope (consumer
#      force-included for pre-deployment scans against an in-progress
#      stand-up).
#   3. Otherwise → auto-detect via AWS API enumeration. In scope iff the
#      consumer has ≥1 resource of this service type.
#
# Detection caches results in a module-level constant for the lifetime of
# the InSpec run so the (potentially-expensive) inventory calls happen
# once per service, not once per control.
#
# ---- Detection is region-scoped, and errors do not mean "absent" -------------
#
# Detection walks the same regions the controls will scan (`scan_regions`, or
# the partition's enabled regions when that is empty). It previously used
# single-region resources, so a workload outside `aws_region` was reported as
# absent and every control for that service became Not Applicable -- a green
# scan that assessed nothing.
#
# Detection now returns three outcomes, not two:
#
#   :present      -> in scope
#   :absent       -> out of scope; Not Applicable is honest here
#   :undetermined -> IN SCOPE. The API could not answer (denied, throttled,
#                    missing SDK), and an unanswerable question is not a "no".
#                    The control runs and reports its own error rather than
#                    disappearing into N/A.
#
# The previous `rescue StandardError; false` made every failure look like
# absence, which is the fail-open posture the paragraph above says this design
# rejects.
#
# Replaces the pre-publish `applicable_services` inclusion-list input.
# Rationale: fail-safe defaults (scan everything in use) rather than
# fail-open (consumer forgets to add X to applicable_services → silent
# coverage gap). Matches FedRAMP-style explicit-deny posture.
#
# Loaded into Inspec::Rule via `::Inspec::Rule.include(...)` per the
# Vendored_Resource_Gaps.md §6 pattern.

module ComputeServiceScopeHelpers
  CACHE = {}
  ERRORS = {}
  REGION_CACHE = {}

  KNOWN_SERVICES = %w[
    ec2 ecs lambda lightsail apprunner batch elasticbeanstalk simspaceweaver
  ].freeze

  # Primary entry point. Returns true if this service should be scanned,
  # false if controls for it should be marked N/A.
  def compute_service_in_scope?(service)
    svc = service.to_s

    excluded = Array(input('excluded_services')).map(&:to_s)
    return false if excluded.include?(svc)

    forced = Array(input('forced_services')).map(&:to_s)
    return true if forced.include?(svc)

    _compute_service_detected?(svc) != :absent
  end

  # Why a service was put in scope without being found. nil when detection
  # answered cleanly. Controls can surface this so an undetermined result is
  # visible in the evidence rather than silently widening scope.
  def compute_service_detection_error(service)
    _compute_service_detected?(service.to_s)
    ERRORS[service.to_s]
  end

  # The regions this run scans, resolved once. Controls pass this to every
  # region-aware resource so detection and assertion agree, and so the partition
  # is enumerated once per run rather than once per resource.
  #
  # Empty only when region resolution itself failed; compute_service_in_scope?
  # reports :undetermined in that case, so controls still run and surface the
  # error rather than silently scanning nothing.
  def compute_scan_regions
    _scan_regions
  end

  private

  def _scan_regions
    return REGION_CACHE[:regions] if REGION_CACHE.key?(:regions)
    override = Array(input('scan_regions')).map(&:to_s).reject(&:empty?)
    if override.empty?
      begin
        override = inspec.backend.compute_client.describe_regions.regions.map(&:region_name)
      rescue StandardError => e
        REGION_CACHE[:error] = "could not enumerate regions (#{e.class}: #{e.message})"
        override = []
      end
    end
    REGION_CACHE[:regions] = override
  end

  # Run the probe in each region. Returns :present on the first hit, :absent if
  # every region answered and none had the service, :undetermined if any region
  # failed to answer and none had it.
  def _probe_regions(svc)
    regions = _scan_regions
    if regions.empty?
      ERRORS[svc] = REGION_CACHE[:error] || "no regions resolved for detection"
      return :undetermined
    end
    failures = {}
    regions.each do |region|
      begin
        return :present if yield(region)
      rescue StandardError => e
        failures[region] = "#{e.class}: #{e.message}"
      end
    end
    return :absent if failures.empty?
    ERRORS[svc] = "detection could not complete in #{failures.size} of " \
                  "#{regions.size} region(s): " +
                  failures.map { |r, m| "#{r}: #{m}" }.join('; ')
    :undetermined
  end

  def _compute_service_detected?(svc)
    return CACHE[svc] if CACHE.key?(svc)
    CACHE[svc] = case svc
                 when 'ec2'              then _detect_ec2
                 when 'ecs'              then _detect_ecs
                 when 'lambda'           then _detect_lambda
                 when 'lightsail'        then _detect_lightsail
                 when 'apprunner'        then _detect_apprunner
                 when 'batch'            then _detect_batch
                 when 'elasticbeanstalk' then _detect_elasticbeanstalk
                 when 'simspaceweaver'   then _detect_simspaceweaver
                 else                         _detect_unknown(svc)
                 end
  end

  # EC2, ECS and Batch have no region-aware inventory resource in this profile,
  # so they are probed with a per-region client directly -- the same shape the
  # multi-region resources use.
  def _detect_ec2
    _probe_regions('ec2') do |region|
      ::Aws::EC2::Client.new(region: region)
        .describe_instances(max_results: 5).reservations.any?
    end
  end

  def _detect_ecs
    _probe_regions('ecs') do |region|
      ::Aws::ECS::Client.new(region: region)
        .list_clusters(max_results: 1).cluster_arns.any?
    end
  end

  def _detect_batch
    _probe_regions('batch') do |region|
      ::Aws::Batch::Client.new(region: region)
        .describe_compute_environments(max_results: 1).compute_environments.any?
    end
  end

  # These four already have region-aware inventory resources. They are now given
  # the same region scope the controls use -- previously they walked every region
  # while the controls honoured `scan_regions`, so a service could be detected in
  # a region the controls never scanned and then pass vacuously.
  def _detect_lambda
    _probe_service('lambda') { aws_lambda_inventory(regions: _scan_regions).functions.any? }
  end

  def _detect_lightsail
    _probe_service('lightsail') { aws_lightsail_inventory(regions: _scan_regions).instances.any? }
  end

  def _detect_apprunner
    _probe_service('apprunner') { aws_apprunner_inventory(regions: _scan_regions).services.any? }
  end

  def _detect_elasticbeanstalk
    _probe_service('elasticbeanstalk') do
      aws_elastic_beanstalk_environments(regions: _scan_regions).environments.any?
    end
  end

  def _detect_simspaceweaver
    _probe_service('simspaceweaver') do
      aws_simspaceweaver_inventory(regions: _scan_regions).simulations.any?
    end
  end

  # Wrapper for the resource-backed probes: the resource already walks regions,
  # so a raise here means detection could not answer at all.
  def _probe_service(svc)
    yield ? :present : :absent
  rescue StandardError => e
    ERRORS[svc] = "detection failed (#{e.class}: #{e.message})"
    :undetermined
  end

  def _detect_unknown(svc)
    ERRORS[svc] = "unknown service '#{svc}': no detector is defined for it. " \
                  "Add one to libraries/_compute_service_scope_helpers.rb."
    :undetermined
  end
end

::Inspec::Rule.include(ComputeServiceScopeHelpers)

# Train-aws doesn't expose a config_client accessor — use the generic
# aws_client(klass) escape hatch per the
# `feedback_inspec_aws_connection_closed_list` memory. Defensive require
# of aws-sdk-configservice so the library loads cleanly in cinc-auditor
# runtimes that haven't bundled the gem.
module AwsConfigClientHelper
  def aws_config_client
    require 'aws-sdk-configservice' unless defined?(Aws::ConfigService::Client)
    inspec.backend.aws_client(Aws::ConfigService::Client)
  end
end

::Inspec::Rule.include(AwsConfigClientHelper)
