# encoding: UTF-8
#
# aws_ec2_amis_in_use — the AMIs this account is ACTUALLY running, discovered
# from the instances, with the provenance signals that identify a rogue one.
#
# Why discovery rather than a declared list alone: CIS 2.1.1 and 2.1.3 are both
# written against a catalogue the operator maintains by hand. That catches an
# instance launched from an unapproved image only if somebody remembered to keep
# the catalogue current, and it offers no help building one -- an adopter starts
# with two failing controls and no way to find out what to put in the list.
#
# So this resource discovers what is in use and exposes provenance directly.
# Three signals need no configuration at all and are meaningful immediately:
#
#   * public?    a publicly-shared AMI running production is a finding on its
#                own, whoever owns it
#   * owner      an image owned by neither this account nor a trusted one is
#                third-party code running with the instance's role
#   * missing    the AMI no longer exists (deregistered), so its provenance can
#                no longer be established at all -- unverifiable, not clean
#
# Two more tighten it when the operator supplies policy: an owner allowlist and
# a naming pattern.
#
# Regions come from the shared walk, so an AMI in a region the old single-client
# code never looked at is now seen. A region that cannot be read sets
# connection_error rather than contributing an empty, clean-looking result.

class AwsEc2AmisInUse < AwsResourceBase
  include RegionScope

  name "aws_ec2_amis_in_use"
  desc "AMIs referenced by running instances, with owner and visibility provenance."

  example "
    describe aws_ec2_amis_in_use do
      its('public_amis')             { should be_empty }
      its('deregistered_amis')       { should be_empty }
      its('untrusted_owner_amis')    { should be_empty }
    end
  "

  attr_reader :amis, :regions, :region_errors, :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override  = Array(opts.delete(:regions))
    @trusted_owners  = Array(opts.delete(:trusted_owners)).map(&:to_s)
    @naming_pattern  = opts.delete(:naming_pattern).to_s
    super(opts)
    validate_parameters
    @regions, scope_error = resolve_region_scope(@aws, region_override)
    @amis, @region_errors = fetch_amis
    @connection_error = scope_error || region_error_summary(@region_errors, @regions.size)
  end

  def to_s
    "AMIs in use (regions: #{@regions.join(', ')})"
  end

  # --- offender lists -------------------------------------------------------

  # Shared with everyone. Owner is irrelevant: nobody should be running a
  # production workload from an image the whole world can read and replace.
  def public_amis
    @amis.select { |a| a[:public] }.map { |a| describe_ami(a) }
  end

  # Referenced by an instance but no longer describable -- deregistered, or in
  # an account that no longer shares it. Provenance is unrecoverable.
  def deregistered_amis
    @amis.select { |a| a[:missing] }.map { |a| describe_ami(a) }
  end

  # Owned by neither this account nor an owner the operator trusts. Empty
  # trusted list means "this account only", which is the strict reading and the
  # right default -- a marketplace or community image is a deliberate decision
  # and should be declared.
  def untrusted_owner_amis
    @amis.reject { |a| a[:missing] }
         .reject { |a| trusted_owner?(a[:owner_id]) }
         .map { |a| describe_ami(a) }
  end

  # Only meaningful when the operator declares a convention.
  def amis_not_matching_pattern
    return [] if @naming_pattern.empty?
    rx = Regexp.new(@naming_pattern)
    @amis.reject { |a| a[:missing] }
         .reject { |a| rx.match?(a[:name].to_s) }
         .map { |a| describe_ami(a) }
  end

  def amis_not_in(approved)
    allow = Array(approved).map(&:to_s)
    return [] if allow.empty?
    @amis.reject { |a| allow.include?(a[:image_id]) }.map { |a| describe_ami(a) }
  end

  # Every distinct AMI in use, formatted for an operator populating an
  # allowlist. This is the half that makes the declared-catalogue controls
  # actionable instead of merely failing.
  def inventory
    @amis.map { |a| describe_ami(a) }
  end

  def image_ids
    @amis.map { |a| a[:image_id] }
  end

  private

  def trusted_owner?(owner_id)
    return true if owner_id.to_s == account_id.to_s
    @trusted_owners.include?(owner_id.to_s)
  end

  def account_id
    @account_id ||= begin
      @aws.sts_client.get_caller_identity.account
    rescue StandardError
      nil
    end
  end

  def describe_ami(a)
    bits = ["#{a[:image_id]} (#{a[:region]})"]
    bits << "name=#{a[:name]}" if a[:name]
    bits << "owner=#{a[:owner_id]}" if a[:owner_id]
    bits << "PUBLIC" if a[:public]
    bits << "DEREGISTERED" if a[:missing]
    bits << "instances=#{Array(a[:instance_ids]).join(',')}" if a[:instance_ids]
    bits.join(' ')
  end

  def fetch_amis
    each_region_collecting(@regions) do |region|
      ec2 = ::Aws::EC2::Client.new(region: region)
      in_use = image_ids_in_use(ec2)
      next [] if in_use.empty?
      described = describe_images(ec2, in_use.keys)
      in_use.map do |image_id, instance_ids|
        img = described[image_id]
        if img.nil?
          { image_id: image_id, region: region, instance_ids: instance_ids, missing: true }
        else
          {
            image_id:      image_id,
            region:        region,
            instance_ids:  instance_ids,
            name:          img.name,
            owner_id:      img.owner_id,
            public:        img.public,
            creation_date: img.creation_date,
            missing:       false,
          }
        end
      end
    end
  end

  # image_id => [instance_id, ...] for everything not terminated.
  def image_ids_in_use(ec2)
    acc = {}
    token = nil
    loop do
      args = { filters: [{ name: "instance-state-name", values: %w[running stopped pending stopping] }] }
      args[:next_token] = token if token
      resp = ec2.describe_instances(args)
      resp.reservations.each do |r|
        r.instances.each do |i|
          next if i.image_id.nil?
          (acc[i.image_id] ||= []) << i.instance_id
        end
      end
      token = resp.next_token
      break unless token
    end
    acc
  end

  # describe_images tolerates ids it cannot see by omitting them, so anything
  # absent from the response is treated as missing rather than assumed fine.
  def describe_images(ec2, ids)
    out = {}
    ids.each_slice(100) do |batch|
      resp = ec2.describe_images(image_ids: batch)
      Array(resp.images).each { |img| out[img.image_id] = img }
    rescue ::Aws::EC2::Errors::InvalidAMIIDNotFound
      batch.each do |id|
        begin
          r = ec2.describe_images(image_ids: [id])
          Array(r.images).each { |img| out[img.image_id] = img }
        rescue ::Aws::Errors::ServiceError
          next
        end
      end
    end
    out
  end
end
