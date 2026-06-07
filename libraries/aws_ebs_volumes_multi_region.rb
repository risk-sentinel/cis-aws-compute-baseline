# Multi-region EBS volume inventory. The vendored inspec-aws `aws_ebs_volumes`
# resource only queries the AwsConnection's CURRENT region, so volumes in any
# other region are invisible to the scan (silent under-coverage — a control
# passes against an empty set). This resource walks each region in
# `input('scan_regions')` (or every region when that is empty) with a per-region
# EC2 client, mirroring `aws_ebs_snapshot_public_access`. For C-2.2.1 / C-2.2.4.
#
# Columns mirror the stock `aws_ebs_volumes` so `.where(encrypted: false)`,
# `.where(state: 'available')`, and `.volume_ids` behave identically.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsEbsVolumesMultiRegion < AwsResourceBase
  name "aws_ebs_volumes_multi_region"
  desc "Multi-region EBS volume inventory (CIS 2.2.1 / 2.2.4)."
  example "
    describe aws_ebs_volumes_multi_region(regions: input('scan_regions')) do
      its('where { encrypted == false }.volume_ids') { should be_empty }
    end
  "

  FilterTable.create
    .register_column(:volume_ids,  field: :volume_id)
    .register_column(:encrypted,   field: :encrypted)
    .register_column(:states,      field: :state)
    .register_column(:regions,     field: :region)
    .register_column(:sizes,       field: :size)
    .register_column(:kms_key_ids, field: :kms_key_id)
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
    "EBS volumes (multi-region: #{@regions.join(', ')})"
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
            client.describe_volumes(next_token: next_token)
          rescue ::Aws::Errors::ServiceError => e
            Inspec::Log.warn("aws_ebs_volumes_multi_region: #{region} describe_volumes failed: #{e.message}")
            break
          end
        Array(resp.volumes).each do |v|
          rows << {
            volume_id:  v.volume_id,
            encrypted:  v.encrypted,
            state:      v.state,
            region:     region,
            size:       v.size,
            kms_key_id: v.kms_key_id,
          }
        end
        break if resp.next_token.nil? || resp.next_token.empty?
        next_token = resp.next_token
      end
    end
    rows
  end
end
