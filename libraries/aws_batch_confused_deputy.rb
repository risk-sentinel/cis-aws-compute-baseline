# encoding: UTF-8
#
# aws_batch_confused_deputy — VERIFY (don't trust) the AWS Batch service-role
# confused-deputy posture (CIS §8.2). Enumerates Batch compute-environment
# service roles and checks each role's trust policy for an aws:SourceAccount or
# aws:SourceArn condition (the confused-deputy guardrail).
#
# Batch is NOT in inspec-aws's AwsConnection closed list -> aws_client(klass)
# escape hatch (memory feedback_inspec_aws_connection_closed_list). IAM trust
# policies via the closed-list iam_client.
#
#   describe aws_batch_confused_deputy do
#     its('roles_without_source_conditions') { should be_empty }
#   end
#
# CAVEAT (exec_validated: false): not yet exec-verified against a live account.
# The assume-role-policy is URL-encoded JSON; the condition-key match is a
# case-insensitive substring on aws:sourceaccount / aws:sourcearn. Validate
# against a real Batch + IAM configuration before relying on a FAIL.

class AwsBatchConfusedDeputy < AwsResourceBase
  name "aws_batch_confused_deputy"
  desc "Batch service roles whose trust policy lacks aws:SourceAccount/aws:SourceArn."
  example "
    describe aws_batch_confused_deputy do
      its('roles_without_source_conditions') { should be_empty }
    end
  "

  attr_reader :service_roles, :roles_without_source_conditions

  def initialize(opts = {})
    super(opts)
    @service_roles = []
    @roles_without_source_conditions = []
    catch_aws_errors do
      require "json"
      require "cgi"
      batch = @aws.aws_client(Aws::Batch::Client)
      iam   = @aws.iam_client

      next_token = nil
      loop do
        resp = batch.describe_compute_environments(next_token: next_token)
        Array(resp.compute_environments).each do |ce|
          @service_roles << ce.service_role unless ce.service_role.to_s.empty?
        end
        next_token = resp.next_token
        break if next_token.nil? || next_token.to_s.empty?
      end

      @service_roles.uniq.each do |arn|
        role_name = arn.split("/").last
        encoded   = iam.get_role(role_name: role_name).role.assume_role_policy_document.to_s
        policy    = JSON.parse(CGI.unescape(encoded))
        guarded = Array(policy["Statement"]).any? do |st|
          cond = st["Condition"] || {}
          cond.values.flat_map { |h| h.is_a?(Hash) ? h.keys : [] }
              .map { |k| k.to_s.downcase }
              .any? { |k| k.include?("aws:sourceaccount") || k.include?("aws:sourcearn") }
        end
        @roles_without_source_conditions << role_name unless guarded
      end
    end
  end

  def to_s
    "AWS Batch service-role confused-deputy posture"
  end
end
