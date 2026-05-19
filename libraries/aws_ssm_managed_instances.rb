# Per-region join of EC2 instances against SSM-managed-instance
# registrations. For cis-aws-compute C-2.9 (Ensure use of AWS Systems
# Manager to manage EC2 instances).
#
# `ssm.describe_instance_information` returns the SSM agent's view of
# managed instances; we cross-reference against `ec2.describe_instances`
# (filter on running) to find running EC2 instances NOT registered in
# SSM. The offender list is `unmanaged_running_instances`.
#
# Per-region instantiation (consistent with other compute libraries).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

require "set"

class AwsSsmManagedInstances < AwsResourceBase
  name "aws_ssm_managed_instances"
  desc "EC2 running instances not registered in SSM (CIS 2.9)."
  example "
    describe aws_ssm_managed_instances do
      its('unmanaged_running_instances') { should be_empty }
    end
  "

  attr_reader :managed_instance_ids, :running_instance_ids, :unmanaged_running_instances

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @managed_instance_ids = []
    @running_instance_ids = []
    @unmanaged_running_instances = []
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "EC2 running instances unmanaged by SSM"
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
    managed = list_managed_in_region(region).to_set
    @managed_instance_ids.concat(managed.to_a)
    list_running_in_region(region).each do |inst|
      @running_instance_ids << inst[:instance_id]
      next if managed.include?(inst[:instance_id])
      @unmanaged_running_instances << inst
    end
  end

  def list_managed_in_region(region)
    ids = []
    client = ::Aws::SSM::Client.new(region: region)
    next_token = nil
    loop do
      resp =
        begin
          client.describe_instance_information(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_ssm_managed_instances: #{region} describe_instance_information failed: #{e.message}")
          return ids
        end
      Array(resp.instance_information_list).each do |i|
        ids << i.instance_id if i.instance_id&.start_with?("i-")
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    ids
  end

  def list_running_in_region(region)
    rows = []
    client = ::Aws::EC2::Client.new(region: region)
    next_token = nil
    loop do
      resp =
        begin
          client.describe_instances(
            filters: [{ name: "instance-state-name", values: ["running"] }],
            next_token: next_token,
          )
        rescue ::Aws::Errors::ServiceError => e
          Inspec::Log.warn("aws_ssm_managed_instances: #{region} describe_instances failed: #{e.message}")
          return rows
        end
      Array(resp.reservations).each do |r|
        Array(r.instances).each do |i|
          rows << { region: region, instance_id: i.instance_id, image_id: i.image_id, instance_type: i.instance_type }
        end
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    rows
  end
end
