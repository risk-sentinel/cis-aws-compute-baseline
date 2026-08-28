# encoding: UTF-8
#
# _region_scope_helpers — one region walk, shared by every regional resource.
#
# BUG THIS FIXES: resources bound to a single `@aws.<service>_client` only ever
# see the region named by `aws_region`. A workload in any other region is not
# assessed, and the control does not fail -- it finds nothing and passes. Users
# running outside the region we scan reported whole services reading as clean or
# Not Applicable while their estate went unexamined.
#
# The second half of the bug is subtler and was present even in the resources
# that already walked regions: a region that denied the call logged a warning and
# contributed zero rows, so an inaccessible region was indistinguishable from an
# empty one. `Inspec::Log.warn` is not evidence -- nothing reads it, and the HDF
# says PASS. Region failures are therefore collected and surfaced through the
# `connection_error` convention this profile already uses, which renders as a
# skip with rationale rather than a pass.
#
# The leading underscore sorts this ahead of the resources that include it, in
# InSpec's alphabetical library-load order.
#
# Resource scope cannot call `input()` -- it raises there -- so the region
# override is always passed in by the caller rather than read here.

module RegionScope
  # Resolve which regions to walk.
  #
  # `override` (the consumer's `scan_regions`) wins when non-empty. Otherwise the
  # partition's enabled regions, which narrows to GovCloud or any other partition
  # automatically because describe_regions is answered by the caller's endpoint.
  #
  # Returns [regions, error]. A nil error means the list is trustworthy; a
  # non-nil error means we could not establish scope at all, which callers must
  # surface rather than treat as "no regions, nothing to check".
  def resolve_region_scope(aws, override = [])
    wanted = Array(override).map(&:to_s).reject(&:empty?)
    return [wanted, nil] unless wanted.empty?

    begin
      regions = aws.compute_client.describe_regions.regions.map(&:region_name)
      return [[], "describe_regions returned no regions"] if regions.empty?
      [regions, nil]
    rescue ::Aws::Errors::ServiceError, ::Aws::Errors::MissingRegionError => e
      [[], "could not enumerate regions (#{e.class}: #{e.message})"]
    end
  end

  # Walk regions, collecting rows. The block is called with each region name and
  # should return an array of rows for it.
  #
  # Returns [rows, errors] where errors maps region => message. A region that
  # errors contributes no rows AND an entry in errors, so the caller can tell the
  # two apart. Callers must not treat a non-empty errors hash as a clean result.
  def each_region_collecting(regions)
    rows = []
    errors = {}
    Array(regions).each do |region|
      begin
        rows.concat(Array(yield(region)))
      rescue ::Aws::Errors::ServiceError => e
        errors[region] = "#{e.class}: #{e.message}"
      rescue StandardError => e
        errors[region] = "#{e.class}: #{e.message}"
      end
    end
    [rows, errors]
  end

  # Route a single-target lookup to the right region.
  #
  # An ARN carries its own region, so an identifier that is one answers the
  # question by itself. Otherwise an explicit `region:` wins, and failing both we
  # fall back to the default client's region -- which is correct when the caller
  # passed a bare name, since a bare name is only meaningful in one region
  # anyway.
  def client_region_for(identifier, explicit = nil)
    return explicit.to_s unless explicit.to_s.empty?
    parts = identifier.to_s.split(':')
    return parts[3] if parts.length > 3 && parts[0] == 'arn' && !parts[3].to_s.empty?
    nil
  end

  # Render region failures as a connection_error string, or nil when every region
  # answered. Kept separate so a resource can decide whether partial data is
  # usable, but the default is that it is not.
  def region_error_summary(errors, scanned)
    return nil if errors.nil? || errors.empty?
    detail = errors.map { |r, m| "#{r}: #{m}" }.join("; ")
    "#{errors.size} of #{scanned} region(s) could not be read -- #{detail}. " \
      "Results are incomplete; treat this as unassessed rather than clean."
  end
end
