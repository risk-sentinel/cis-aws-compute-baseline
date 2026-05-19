# Per-region enumeration of EBS snapshots whose `createVolumePermission`
# attribute includes `Group: all` (= public). For cis-aws-compute C-2.2.2
# (Ensure Public Access to EBS Snapshots is Disabled).
#
# Vendored inspec-aws's `aws_ebs_snapshots` doesn't expose
# createVolumePermissions; per-snapshot `describe_snapshot_attribute`
# is the only API path. This costs one extra call per snapshot —
# acceptable since the typical account has dozens, not thousands.
#
# Per-region instantiation (consistent with other compute libraries).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsEbsSnapshotPublicAccess < AwsResourceBase
  name "aws_ebs_snapshot_public_access"
  desc "EBS snapshots with public createVolumePermission (CIS 2.2.2)."
  example "
    describe aws_ebs_snapshot_public_access do
      its('public_snapshots') { should be_empty }
    end
  "

  attr_reader :public_snapshots

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @public_snapshots = []
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "EBS snapshots with public createVolumePermission"
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
    client = ::Aws::EC2::Client.new(region: region)
    next_token = nil
    loop do
      resp =
        begin
          client.describe_snapshots(owner_ids: ["self"], next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_ebs_snapshot_public_access: #{region} describe_snapshots failed: #{e.message}")
          return
        end
      Array(resp.snapshots).each { |s| check_snapshot(client, region, s) }
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
  end

  def check_snapshot(client, region, snapshot)
    attr =
      begin
        client.describe_snapshot_attribute(snapshot_id: snapshot.snapshot_id, attribute: "createVolumePermission")
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_ebs_snapshot_public_access: #{region} describe_snapshot_attribute(#{snapshot.snapshot_id}) failed: #{e.message}")
        return
      end
    permissions = Array(attr.create_volume_permissions)
    return if permissions.empty?
    is_public = permissions.any? { |p| p.respond_to?(:group) && p.group.to_s == "all" }
    return unless is_public
    @public_snapshots << { region: region, snapshot_id: snapshot.snapshot_id, description: snapshot.description }
  end
end
