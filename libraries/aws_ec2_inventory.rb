require "time"

# EC2 inventory helper — wraps describe_instances and computes the
# offender lists section 2 needs. Targets running + stopped instances
# (skips terminated). Used by future consumers; the consumer auto-skips
# section 2 because it doesn't run user-facing EC2.
#
# Offender lists:
#   .instances_older_than(days)              (CIS 2.5)
#   .instances_missing_detailed_monitoring   (CIS 2.6)
#   .instances_in_default_security_group     (CIS 2.7)
#   .instances_without_imdsv2                (CIS 2.8)
#   .enis_unattached                         (CIS 2.10)
#   .instances_without_delete_on_term        (CIS 2.12)
#   .instances_missing_required_tags(keys)   (CIS 2.3 / 2.4 fallback)
#
# Each returns an array of strings or maps suitable for offender display.

class AwsEc2Inventory < AwsResourceBase
  name "aws_ec2_inventory"
  desc "EC2 inventory: instances + ENIs + offender helpers."

  example "
    describe aws_ec2_inventory do
      its('instances_without_imdsv2') { should be_empty }
    end
  "

  attr_reader :instances

  def initialize(opts = {})
    super(opts)
    validate_parameters
    @instances = fetch_instances
  end

  def fetch_instances
    rows = []
    token = nil
    loop do
      resp = nil
      catch_aws_errors do
        args = { filters: [{ name: "instance-state-name", values: %w[running stopped pending stopping] }] }
        args[:next_token] = token if token
        resp = @aws.compute_client.describe_instances(args)
      end
      break unless resp
      resp.reservations.each do |r|
        r.instances.each { |i| rows << i.to_h }
      end
      token = resp.next_token
      break unless token
    end
    rows
  end

  def instances_older_than(days)
    threshold = Time.now - (days * 86_400)
    @instances.select { |i| i[:launch_time] && Time.parse(i[:launch_time].to_s) < threshold }
              .map { |i| "#{i[:instance_id]}:age_days=#{((Time.now - Time.parse(i[:launch_time].to_s)) / 86_400).to_i}" }
  end

  def instances_missing_detailed_monitoring
    @instances.reject { |i| i.dig(:monitoring, :state).to_s == "enabled" }.map { |i| i[:instance_id] }
  end

  def instances_in_default_security_group
    @instances.each_with_object([]) do |i, acc|
      sgs = Array(i[:security_groups])
      default_sgs = sgs.select { |sg| sg[:group_name].to_s == "default" }
      next if default_sgs.empty?
      acc << "#{i[:instance_id]}:default_sg=#{default_sgs.map { |sg| sg[:group_id] }.join(',')}"
    end
  end

  def instances_without_imdsv2
    @instances.reject { |i| i.dig(:metadata_options, :http_tokens).to_s == "required" }
              .map { |i| "#{i[:instance_id]}:http_tokens=#{i.dig(:metadata_options, :http_tokens) || 'unset'}" }
  end

  def instances_without_delete_on_term
    @instances.each_with_object([]) do |i, acc|
      bdms = Array(i[:block_device_mappings])
      bad = bdms.reject { |bdm| bdm.dig(:ebs, :delete_on_termination) == true }
      next if bad.empty?
      acc << "#{i[:instance_id]}:#{bad.map { |b| b[:device_name] }.join(',')}"
    end
  end

  def instances_missing_required_tags(required_keys)
    keys = Array(required_keys)
    @instances.each_with_object([]) do |i, acc|
      tag_keys = Array(i[:tags]).map { |t| t[:key] }
      if keys.empty?
        acc << i[:instance_id] if tag_keys.empty?
      else
        missing = keys - tag_keys
        acc << "#{i[:instance_id]}:missing=#{missing.join(',')}" unless missing.empty?
      end
    end
  end

  def enis_unattached
    rows = []
    token = nil
    loop do
      resp = nil
      catch_aws_errors do
        args = { filters: [{ name: "status", values: ["available"] }] }
        args[:next_token] = token if token
        resp = @aws.compute_client.describe_network_interfaces(args)
      end
      break unless resp
      rows.concat(resp.network_interfaces.map(&:to_h))
      token = resp.next_token
      break unless token
    end
    rows.map { |eni| eni[:network_interface_id] }
  end

  def to_s
    "AWS EC2 inventory (instances=#{@instances.size})"
  end
end
