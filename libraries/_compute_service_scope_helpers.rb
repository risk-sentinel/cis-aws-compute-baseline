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
# Replaces the pre-publish `applicable_services` inclusion-list input.
# Rationale: fail-safe defaults (scan everything in use) rather than
# fail-open (consumer forgets to add X to applicable_services → silent
# coverage gap). Matches FedRAMP-style explicit-deny posture.
#
# Loaded into Inspec::Rule via `::Inspec::Rule.include(...)` per the
# Vendored_Resource_Gaps.md §6 pattern.

module ComputeServiceScopeHelpers
  CACHE = {}

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

    _compute_service_detected?(svc)
  end

  private

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

  # Each detector is `rescue`-wrapped so a missing-perm / missing-SDK /
  # missing-resource situation degrades to out-of-scope (false) rather
  # than crashing the whole profile. Operators investigating empty
  # results can run individual inventory resources directly to see the
  # underlying error.
  def _detect_ec2
    aws_ec2_instances.entries.any?
  rescue StandardError
    false
  end

  def _detect_ecs
    aws_ecs_clusters.entries.any?
  rescue StandardError
    false
  end

  def _detect_lambda
    # Vendored inspec-aws ships `aws_lambdas` (plural) — `aws_lambda_functions`
    # does NOT exist. The local `aws_lambda_inventory` custom resource is
    # used by the §12 controls and is already part of this profile, so use it
    # here for the auto-detect probe.
    aws_lambda_inventory.functions.any?
  rescue StandardError
    false
  end

  def _detect_lightsail
    aws_lightsail_inventory.instances.any?
  rescue StandardError
    false
  end

  def _detect_apprunner
    aws_apprunner_inventory.services.any?
  rescue StandardError
    false
  end

  def _detect_batch
    aws_batch_compute_environments.entries.any?
  rescue StandardError
    false
  end

  def _detect_elasticbeanstalk
    aws_elastic_beanstalk_environments.environments.any?
  rescue StandardError
    false
  end

  def _detect_simspaceweaver
    aws_simspaceweaver_inventory.simulations.any?
  rescue StandardError
    false
  end

  def _detect_unknown(svc)
    Inspec::Log.warn(
      "compute_service_in_scope?: unknown service '#{svc}'; assuming out-of-scope. " \
      "Add a detector rule to libraries/_compute_service_scope_helpers.rb."
    )
    false
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
