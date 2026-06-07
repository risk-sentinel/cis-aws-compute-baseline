# Multi-region EBS snapshot inventory (self-owned). The vendored inspec-aws
# `aws_ebs_snapshots` resource only queries the AwsConnection's CURRENT region,
# so snapshots in any other region are invisible to the scan. This resource
# walks each region in `input('scan_regions')` (or every region when empty) with
# a per-region EC2 client, mirroring `aws_ebs_snapshot_public_access`. For
# C-2.2.3 (snapshot encryption).
#
# Columns mirror the stock `aws_ebs_snapshots` so `.where(encrypted: false)` and
# `.snapshot_ids` behave identically. Scoped to owner_ids=['self'] (the account's
# own snapshots), matching the CIS intent.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsEbsSnapshotsMultiRegion < AwsResourceBase
  name "aws_ebs_snapshots_multi_region"
  desc "Multi-region self-owned EBS snapshot inventory (CIS 2.2.3)."
  example "
    describe aws_ebs_snapshots_multi_region(regions: input('scan_regions')) do
      its('where { encrypted == false }.snapshot_ids') { should be_empty }
    end
  "

  FilterTable.create
    .register_column(:snapshot_ids, field: :snapshot_id)
    .register_column(:encrypted,    field: :encrypted)
    .register_column(:regions,      field: :region)
    .install_filter_methods_on_resource(self, :table)

  attr_reader :table

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @regions = region_override.empty? ? fetch_default_regions : region_override
    @table = fetch_data
  end

  def exists?
    !@table.empty?
  end

  def to_s
    "EBS snapshots (multi-region: #{@regions.join(', ')})"
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
    rows = []
    @regions.each do |region|
      client = ::Aws::EC2::Client.new(region: region)
      next_token = nil
      loop do
        resp =
          begin
            client.describe_snapshots(owner_ids: ["self"], next_token: next_token)
          rescue ::Aws::Errors::ServiceError => e
            Inspec::Log.warn("aws_ebs_snapshots_multi_region: #{region} describe_snapshots failed: #{e.message}")
            break
          end
        Array(resp.snapshots).each do |s|
          rows << { snapshot_id: s.snapshot_id, encrypted: s.encrypted, region: region }
        end
        break if resp.next_token.nil? || resp.next_token.empty?
        next_token = resp.next_token
      end
    end
    rows
  end
end
