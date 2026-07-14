require_relative '../test_helper'

class TestSlack < Minitest::Test
  WEBHOOK_URL = 'https://hooks.slack.com/services/test/test/test'

  def pkg(tier: 'standard')
    StackWatch::Package.new(name: 'django', ecosystem: 'PyPI', tier: tier)
  end

  def vuln(fixed: '4.2.1')
    StackWatch::Vuln.new(
      id: 'CVE-2024-12345',
      cvss_score: '9.8',
      summary: 'Remote code execution in Django',
      affected: '>=3.0.0',
      fixed: fixed,
      url: 'https://osv.dev/vulnerability/CVE-2024-12345'
    )
  end

  def stub_slack(status: 200)
    stub_request(:post, WEBHOOK_URL).to_return(status: status, body: 'ok')
  end

  def notify(tier: 'standard', fixed: '4.2.1', mention: false)
    StackWatch::Notifiers::Slack.new(WEBHOOK_URL).post_alerts(
      [{ package: pkg(tier: tier), vuln: vuln(fixed: fixed), mention: mention }]
    )
  end

  def test_notify_without_mention_has_no_here
    stub_slack
    notify(mention: false)
    assert_requested(:post, WEBHOOK_URL) { |req| !JSON.parse(req.body)['text'].include?('<!here>') }
  end

  def test_notify_with_mention_includes_here
    stub_slack
    notify(mention: true)
    assert_requested(:post, WEBHOOK_URL) { |req| JSON.parse(req.body)['text'].include?('<!here>') }
  end

  def test_notify_posts_all_required_fields
    stub_slack
    notify
    assert_requested(:post, WEBHOOK_URL) do |req|
      text = JSON.parse(req.body)['text']
      text.include?('CVE-2024-12345') &&
        text.include?('9.8')          &&
        text.include?('Django')       &&
        text.include?('4.2.1')        &&
        text.include?('osv.dev')
    end
  end

  def test_no_patch_when_fixed_nil
    stub_slack
    notify(fixed: nil)
    assert_requested(:post, WEBHOOK_URL) { |req| JSON.parse(req.body)['text'].include?('no patch') }
  end

  def test_empty_alerts_posts_nothing
    stub_slack
    StackWatch::Notifiers::Slack.new(WEBHOOK_URL).post_alerts([])
    assert_not_requested(:post, WEBHOOK_URL)
  end

  def test_batches_at_most_ten_per_message
    stub_slack
    items = Array.new(23) do |i|
      { package: pkg, vuln: vuln.tap { |v| v.id = "CVE-#{i}" }, mention: false }
    end
    StackWatch::Notifiers::Slack.new(WEBHOOK_URL).post_alerts(items)
    assert_requested(:post, WEBHOOK_URL, times: 3) # 10 + 10 + 3
  end

  def test_caps_at_five_messages_and_notes_overflow
    stub_slack
    items = Array.new(63) { |i| { package: pkg, vuln: vuln.tap { |v| v.id = "CVE-#{i}" }, mention: false } }
    StackWatch::Notifiers::Slack.new(WEBHOOK_URL).post_alerts(items)
    assert_requested(:post, WEBHOOK_URL, times: 5) # 63 -> 5 messages, not 7
    # 5 batches * 10 = 50 sent, 13 suppressed, noted on the last message
    assert_requested(:post, WEBHOOK_URL) { |req| JSON.parse(req.body)['text'].include?('+13 more') }
  end

  def test_here_applied_once_when_any_item_warrants_it
    stub_slack
    items = [
      { package: pkg, vuln: vuln, mention: false },
      { package: pkg, vuln: vuln, mention: true }
    ]
    StackWatch::Notifiers::Slack.new(WEBHOOK_URL).post_alerts(items)
    assert_requested(:post, WEBHOOK_URL) { |req| JSON.parse(req.body)['text'].scan('<!here>').size == 1 }
  end

  def test_http_error_raises_slack_error
    stub_request(:post, WEBHOOK_URL).to_return(status: 500, body: 'error')
    assert_raises(StackWatch::Notifiers::SlackError) { notify }
  end

  def test_timeout_raises_slack_error
    stub_request(:post, WEBHOOK_URL).to_timeout
    assert_raises(StackWatch::Notifiers::SlackError) { notify }
  end
end
