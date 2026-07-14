require_relative '../test_helper'

class TestOSV < Minitest::Test
  OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
  OSV_VULN_URL  = 'https://api.osv.dev/v1/vulns/'

  def pkg(name: 'django', ecosystem: 'PyPI', tier: 'standard', version: nil)
    StackWatch::Package.new(name: name, ecosystem: ecosystem, tier: tier, version: version)
  end

  def stub_batch(body:, status: 200)
    stub_request(:post, OSV_BATCH_URL)
      .to_return(status: status, body: body, headers: { 'Content-Type' => 'application/json' })
  end

  # --- fetch_all: cheap querybatch returning id-only stubs ---

  def test_fetch_all_returns_stubs
    stub_batch(body: JSON.generate(results: [
                 { vulns: [{ 'id' => 'CVE-2024-27351', 'modified' => '2026-01-01T00:00:00Z' }] }
               ]))
    p   = pkg
    res = StackWatch::Sources::OSV.new([p]).fetch_all

    assert_equal 1, res[p].size
    assert_instance_of StackWatch::Stub, res[p][0]
    assert_equal 'CVE-2024-27351', res[p][0].id
    assert_equal '2026-01-01T00:00:00Z', res[p][0].modified
  end

  def test_fetch_all_multiple_packages
    stub_batch(body: JSON.generate(results: [
                 { vulns: [{ 'id' => 'CVE-A', 'modified' => 'x' }] },
                 { vulns: [] }
               ]))
    p1 = pkg(name: 'django', ecosystem: 'PyPI')
    p2 = pkg(name: 'next',   ecosystem: 'npm')
    res = StackWatch::Sources::OSV.new([p1, p2]).fetch_all

    assert_equal 1, res[p1].size
    assert_equal 0, res[p2].size
  end

  def test_fetch_all_sends_version_when_pinned
    stub_batch(body: JSON.generate(results: [{ vulns: [] }]))
    StackWatch::Sources::OSV.new([pkg(name: 'rails', ecosystem: 'RubyGems', version: '8.0.5')]).fetch_all

    assert_requested(:post, OSV_BATCH_URL) do |req|
      q = JSON.parse(req.body)['queries'][0]
      q['version'] == '8.0.5' && q['package']['name'] == 'rails'
    end
  end

  def test_fetch_all_omits_version_when_absent
    stub_batch(body: JSON.generate(results: [{ vulns: [] }]))
    StackWatch::Sources::OSV.new([pkg]).fetch_all

    assert_requested(:post, OSV_BATCH_URL) { |req| !JSON.parse(req.body)['queries'][0].key?('version') }
  end

  def test_fetch_all_empty_packages_returns_empty_hash
    assert_equal({}, StackWatch::Sources::OSV.new([]).fetch_all)
  end

  def test_empty_vulns_array_in_response
    stub_batch(body: JSON.generate(results: [{ vulns: [] }]))
    p = pkg
    assert_equal [], StackWatch::Sources::OSV.new([p]).fetch_all[p]
  end

  def test_missing_vulns_key_in_response
    stub_batch(body: JSON.generate(results: [{}]))
    p = pkg
    assert_equal [], StackWatch::Sources::OSV.new([p]).fetch_all[p]
  end

  def test_http_error_raises_osv_error
    stub_batch(body: 'Internal error', status: 500)
    assert_raises(StackWatch::Sources::OSVError) { StackWatch::Sources::OSV.new([pkg]).fetch_all }
  end

  def test_timeout_raises_osv_error
    stub_request(:post, OSV_BATCH_URL).to_timeout
    assert_raises(StackWatch::Sources::OSVError) { StackWatch::Sources::OSV.new([pkg]).fetch_all }
  end

  # --- fetch_vuln: on-demand enrichment via the full-record endpoint ---

  def test_fetch_vuln_enriches_from_full_record
    stub_request(:get, "#{OSV_VULN_URL}CVE-2024-27351")
      .to_return(status: 200, body: fixture('osv_vuln_record.json'),
                 headers: { 'Content-Type' => 'application/json' })

    vuln = StackWatch::Sources::OSV.new([]).fetch_vuln('CVE-2024-27351')

    assert_equal 'CVE-2024-27351', vuln.id
    assert_in_delta 7.5, vuln.severity_score, 0.1
    assert_equal '3.2.25', vuln.fixed
    assert_equal '>=3.2.0', vuln.affected
    assert_includes vuln.aliases, 'GHSA-qrr7-9963-x827'
  end

  def test_fetch_vuln_http_error_raises
    stub_request(:get, "#{OSV_VULN_URL}CVE-X").to_return(status: 404, body: 'not found')
    assert_raises(StackWatch::Sources::OSVError) { StackWatch::Sources::OSV.new([]).fetch_vuln('CVE-X') }
  end
end
