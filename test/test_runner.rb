require_relative 'test_helper'
require 'tmpdir'
require 'fileutils'
require 'stringio'

# fetch_all returns lightweight Stubs; fetch_vuln hydrates back to the full Vuln.
# Constructed from { package => [Vuln] } so tests can declare enriched vulns directly.
class FakeSource
  def initialize(results)
    @results = results
    @by_id = {}
    results.each_value { |vulns| vulns.each { |v| @by_id[v.id] = v } }
  end

  def fetch_all
    @results.transform_values do |vulns|
      vulns.map { |v| StackWatch::Stub.new(id: v.id, modified: nil) }
    end
  end

  def fetch_vuln(id)
    @by_id.fetch(id)
  end
end

class FakeNotifier
  attr_reader :notifications, :summaries, :digests

  def initialize
    @notifications = []
    @summaries = []
    @digests = []
  end

  # Flattened so per-alert assertions (notifications[0][:vuln]/[:mention]) still work.
  def post_alerts(items)
    @notifications.concat(items)
  end

  def post_digest(items)
    @digests << items
  end

  def post_summary(alerted, digest_count: 0)
    @summaries << alerted
  end
end

class FailingNotifier
  def post_alerts(_items)
    raise StackWatch::Notifiers::SlackError, 'webhook failed'
  end

  def post_digest(_items)
    raise StackWatch::Notifiers::SlackError, 'webhook failed'
  end

  def post_summary(_alerted, digest_count: 0)
    raise StackWatch::Notifiers::SlackError, 'webhook failed'
  end
end

class TestRunner < Minitest::Test
  def setup
    @tmpdir     = Dir.mktmpdir
    @state_path = File.join(@tmpdir, 'state.json')
    @pkg        = StackWatch::Package.new(name: 'django', ecosystem: 'PyPI', tier: 'critical')
    # High severity + patch available => alerts and @here-worthy.
    @vuln       = stub_vuln(id: 'CVE-2024-99999', summary: 'Test vuln', cvss_score: '8.0',
                            affected: '>=1.0', fixed: '2.0')
    @config     = StackWatch::AppConfig.new(
      packages: [@pkg],
      slack_webhook_url: nil,
      state_path: @state_path,
      max_age_days: nil
    )
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
  end

  def run_with(source:, notifier: nil, config: @config, out: StringIO.new, err: StringIO.new)
    StackWatch::Runner.call(config, stdout: out, stderr: err, source: source, notifier: notifier)
  end

  def test_notifies_new_vulns
    notifier = FakeNotifier.new
    out      = StringIO.new
    count    = run_with(source: FakeSource.new(@pkg => [@vuln]), notifier: notifier, out: out)

    assert_equal 1, count
    assert_match 'CVE-2024-99999', out.string
    assert_equal 1, notifier.notifications.size
    assert_equal 'CVE-2024-99999', notifier.notifications[0][:vuln].id
    assert notifier.notifications[0][:mention], 'high severity + patch => @here'
    assert_equal [1], notifier.summaries
  end

  def test_skips_already_seen_vulns
    state = StackWatch::State.load(@state_path)
    state.mark_seen(@pkg, [stub_vuln(id: 'CVE-2024-99999')])
    state.persist

    notifier = FakeNotifier.new
    count    = run_with(source: FakeSource.new(@pkg => [@vuln]), notifier: notifier)

    assert_equal 0, count
    assert_empty notifier.notifications
    assert_equal [0], notifier.summaries
  end

  def test_persists_state_on_success
    run_with(source: FakeSource.new(@pkg => [@vuln]))

    assert File.exist?(@state_path)
    data = JSON.parse(File.read(@state_path))
    assert_includes data.dig('packages', 'PyPI/django'), 'CVE-2024-99999'
  end

  def test_persists_state_despite_notifier_failure
    assert_raises(StackWatch::Notifiers::SlackError) do
      run_with(source: FakeSource.new(@pkg => [@vuln]), notifier: FailingNotifier.new)
    end

    assert File.exist?(@state_path), 'State must be persisted even when Slack fails'
    data = JSON.parse(File.read(@state_path))
    assert_includes data.dig('packages', 'PyPI/django'), 'CVE-2024-99999'
  end

  def test_alert_batch_failure_persists_all_seen
    pkg2  = StackWatch::Package.new(name: 'next', ecosystem: 'npm', tier: 'standard')
    vuln2 = stub_vuln(id: 'CVE-2024-88888', summary: 'Another vuln', cvss_score: '7.5', fixed: '1.0')

    notifier = FailingNotifier.new
    err = StringIO.new
    assert_raises(StackWatch::Notifiers::SlackError) do
      run_with(source: FakeSource.new(@pkg => [@vuln], pkg2 => [vuln2]), notifier: notifier, err: err)
    end

    data = JSON.parse(File.read(@state_path))
    assert_includes data.dig('packages', 'PyPI/django'), 'CVE-2024-99999'
    assert_includes data.dig('packages', 'npm/next'), 'CVE-2024-88888'
    assert_match 'WARN', err.string
  end

  def test_raises_on_source_failure
    source = FakeSource.new({})
    source.define_singleton_method(:fetch_all) { raise StackWatch::Sources::OSVError, 'API down' }

    assert_raises(StackWatch::Sources::OSVError) { run_with(source: source) }
  end

  def test_enrichment_failure_skips_and_leaves_unseen
    source = FakeSource.new(@pkg => [@vuln])
    source.define_singleton_method(:fetch_vuln) { |_id| raise StackWatch::Sources::OSVError, 'timeout' }
    notifier = FakeNotifier.new
    err = StringIO.new

    count = run_with(source: source, notifier: notifier, err: err)

    assert_equal 0, count
    assert_empty notifier.notifications
    assert_match 'enrichment failed', err.string
    data = JSON.parse(File.read(@state_path))
    refute_includes Array(data.dig('packages', 'PyPI/django')), 'CVE-2024-99999'
  end

  def test_runs_without_notifier
    out   = StringIO.new
    count = run_with(source: FakeSource.new(@pkg => [@vuln]), out: out)

    assert_equal 1, count
    assert_match 'CVE-2024-99999', out.string
  end

  def test_summary_posted_even_when_zero_new
    notifier = FakeNotifier.new
    count    = run_with(source: FakeSource.new(@pkg => []), notifier: notifier)

    assert_equal 0, count
    assert_equal [0], notifier.summaries
  end

  # --- severity routing ---

  def test_drops_below_drop_threshold
    low      = stub_vuln(id: 'CVE-LOW', cvss_score: '3.1', fixed: '1.1')
    notifier = FakeNotifier.new
    count    = run_with(source: FakeSource.new(@pkg => [low]), notifier: notifier)

    assert_equal 0, count
    assert_empty notifier.notifications
    assert_empty notifier.digests
    # still marked seen so it isn't re-fetched daily
    assert_includes JSON.parse(File.read(@state_path)).dig('packages', 'PyPI/django'), 'CVE-LOW'
  end

  def test_medium_severity_is_digested_not_alerted
    med      = stub_vuln(id: 'CVE-MED', cvss_score: '5.5', fixed: '1.1')
    notifier = FakeNotifier.new
    count    = run_with(source: FakeSource.new(@pkg => [med]), notifier: notifier)

    assert_equal 0, count
    assert_empty notifier.notifications
    assert_equal 1, notifier.digests.size
    assert_equal 'CVE-MED', notifier.digests[0][0][:vuln].id
  end

  def test_unknown_severity_is_digested
    unknown  = stub_vuln(id: 'CVE-UNK', cvss_score: 'N/A')
    notifier = FakeNotifier.new
    run_with(source: FakeSource.new(@pkg => [unknown]), notifier: notifier)

    assert_empty notifier.notifications
    assert_equal 1, notifier.digests.size
  end

  def test_no_here_mention_when_no_patch
    unpatched = stub_vuln(id: 'CVE-NOPATCH', cvss_score: '9.0', fixed: nil)
    notifier  = FakeNotifier.new
    count     = run_with(source: FakeSource.new(@pkg => [unpatched]), notifier: notifier)

    assert_equal 1, count, 'high severity still alerts'
    refute notifier.notifications[0][:mention], 'no patch => no @here'
  end

  def test_alias_dedup_across_packages
    pkg2 = StackWatch::Package.new(name: 'rails', ecosystem: 'RubyGems', tier: 'critical')
    a    = stub_vuln(id: 'CVE-1', cvss_score: '8.0', fixed: '1.0', aliases: ['GHSA-x'])
    b    = stub_vuln(id: 'GHSA-x', cvss_score: '8.0', fixed: '1.0', aliases: ['CVE-1'])

    notifier = FakeNotifier.new
    count    = run_with(source: FakeSource.new(@pkg => [a], pkg2 => [b]), notifier: notifier)

    assert_equal 1, count, 'same upstream advisory alerts once across packages'
  end

  def test_retroactive_cve_backfill_is_digested_not_alerted
    # CVE-2022 first published now = a 4-year-old fix just getting a number.
    backfill = stub_vuln(id: 'CVE-2022-48001', cvss_score: '7.8', fixed: '1.1',
                         published: Time.now.utc - (5 * 86_400))
    notifier = FakeNotifier.new
    count    = run_with(source: FakeSource.new(@pkg => [backfill]), notifier: notifier)

    assert_equal 0, count, 'backfill does not alert'
    assert_empty notifier.notifications
    assert_equal 1, notifier.digests.size
    assert_equal 'CVE-2022-48001', notifier.digests[0][0][:vuln].id
  end

  def test_recent_cve_of_current_year_still_alerts
    fresh    = stub_vuln(id: 'CVE-2026-1795', cvss_score: '7.8', fixed: '1.1',
                         published: Time.now.utc - (2 * 86_400))
    notifier = FakeNotifier.new
    count    = run_with(source: FakeSource.new(@pkg => [fresh]), notifier: notifier)

    assert_equal 1, count
    assert_equal 'CVE-2026-1795', notifier.notifications[0][:vuln].id
  end

  # --- age filtering ---

  def test_skips_vulns_older_than_max_age_days
    config = config_with(max_age_days: 30)
    fresh  = stub_vuln(id: 'CVE-FRESH', cvss_score: '8.0', fixed: '1.1',
                       published: Time.now.utc - (5 * 86_400))
    stale  = stub_vuln(id: 'CVE-OLD', cvss_score: '8.0', fixed: '1.1',
                       published: Time.now.utc - (90 * 86_400))

    notifier = FakeNotifier.new
    count    = run_with(source: FakeSource.new(@pkg => [fresh, stale]), notifier: notifier, config: config)

    assert_equal 1, count
    assert_equal(['CVE-FRESH'], notifier.notifications.map { |n| n[:vuln].id })
  end

  def test_skips_withdrawn_vulns_regardless_of_age
    withdrawn = stub_vuln(id: 'CVE-PULLED', cvss_score: '9.0', fixed: '1.1',
                          published: Time.now.utc - (1 * 86_400), withdrawn: Time.now.utc)
    notifier  = FakeNotifier.new
    count     = run_with(source: FakeSource.new(@pkg => [withdrawn]), notifier: notifier)

    assert_equal 0, count
    assert_empty notifier.notifications
  end

  def test_age_filtered_vulns_are_marked_seen
    config = config_with(max_age_days: 30)
    stale  = stub_vuln(id: 'CVE-OLD', cvss_score: '8.0', published: Time.now.utc - (90 * 86_400))

    run_with(source: FakeSource.new(@pkg => [stale]), config: config)

    data = JSON.parse(File.read(@state_path))
    assert_includes Array(data.dig('packages', 'PyPI/django')), 'CVE-OLD'
  end

  def test_max_age_disabled_includes_old_vulns
    config = config_with(max_age_days: nil)
    stale  = stub_vuln(id: 'CVE-OLD', cvss_score: '8.0', fixed: '1.1', published: Time.utc(2018, 9, 5))

    count = run_with(source: FakeSource.new(@pkg => [stale]), config: config)
    assert_equal 1, count
  end

  def test_vuln_with_unknown_publish_date_is_kept
    config  = config_with(max_age_days: 30)
    no_date = stub_vuln(id: 'CVE-NO-DATE', cvss_score: '8.0', fixed: '1.1', published: nil)

    count = run_with(source: FakeSource.new(@pkg => [no_date]), config: config)
    assert_equal 1, count
  end

  private

  def config_with(**overrides)
    StackWatch::AppConfig.new(@config.to_h.merge(overrides))
  end
end
