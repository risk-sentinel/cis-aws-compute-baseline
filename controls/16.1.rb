# encoding: UTF-8

control 'C-16.1' do
  title 'Ensure communications between your applications and clients is encrypted.'
  desc  "
    SimSpace Weaver doesn't manage communications between your apps and the clients.

    Be sure to implement some form of authentication and encryption for all client sessions while using SimSpace Weaver.
  "
  desc  'rationale', "
    SimSpace Weaver doesn't manage communications between your apps and the clients.

    Be sure to implement some form of authentication and encryption for all client sessions while using SimSpace Weaver.
  "
  desc  'check', "
    There is no setting for encryption setup for your clients and applications within SimSpace Weaver service.  For this audit you have to confirm that the communication is configured in the app and the client with encryption to protect that traffic.
  "
  desc  'fix', "
    Confirm that the communication you have configured between you application and clients that run inside of SimSpace Weaver are encrypted.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '16.1'
  tag cis_rid:               '16.1'
  tag cis_benchmark:         'CIS AWS Compute Services Benchmark v1.1.0'
  tag cis_rule_id:           'SV-1601r1_rule'
  tag cis_version:           '1.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = compute_service_in_scope?('simspaceweaver')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("SIMSPACEWEAVER out of scope (partition=#{input('aws_partition')}, in-scope=#{applicable_service})") do
    applicable
  end

  inv = aws_simspaceweaver_inventory(regions: input('scan_regions'))
  if inv.connection_error
    describe 'AWS SimSpace Weaver inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('simulations_without_tls') { should be_empty }
    end
  end
end
