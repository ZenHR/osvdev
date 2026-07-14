require_relative 'test_helper'
require 'tmpdir'

class TestConfig < Minitest::Test
  def write_yml(content, dir: @tmpdir)
    path = File.join(dir, 'stack.yml')
    File.write(path, content)
    path
  end

  def setup
    @tmpdir = Dir.mktmpdir
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
  end

  VALID_YML = <<~YAML
    notifications:
      slack:
        webhook_url: "https://hooks.slack.com/test"
    packages:
      - name: django
        ecosystem: PyPI
        tier: critical
      - name: next
        ecosystem: npm
        tier: standard
  YAML

  def test_load_valid_config
    path = write_yml(VALID_YML)
    cfg  = StackWatch::Config.load(path: path, env: {})

    assert_equal 2, cfg.packages.size
    assert_equal 'django', cfg.packages[0].name
    assert_equal 'PyPI',   cfg.packages[0].ecosystem
    assert cfg.packages[0].critical?
    refute cfg.packages[1].critical?
    assert_equal 'https://hooks.slack.com/test', cfg.slack_webhook_url
  end

  def test_missing_packages_defaults_to_empty
    path = write_yml("notifications:\n  slack:\n    webhook_url: https://x\n")
    cfg  = StackWatch::Config.load(path: path, env: {})
    assert_empty cfg.packages
  end

  def test_slack_webhook_from_env_overrides_yaml
    path = write_yml(VALID_YML)
    cfg  = StackWatch::Config.load(path: path, env: { 'STACKWATCH_SLACK_WEBHOOK' => 'https://env-hook' })
    assert_equal 'https://env-hook', cfg.slack_webhook_url
  end

  def test_state_path_precedence_flag_wins
    path = write_yml(VALID_YML)
    cfg  = StackWatch::Config.load(path: path, state_path_override: '/flag/state.json',
                                   env: { 'STACKWATCH_STATE_PATH' => '/env/state.json' })
    assert_equal '/flag/state.json', cfg.state_path
  end

  def test_state_path_precedence_env_over_default
    path = write_yml(VALID_YML)
    cfg  = StackWatch::Config.load(path: path, env: { 'STACKWATCH_STATE_PATH' => '/env/state.json',
                                                      'STACKWATCH_SLACK_WEBHOOK' => 'https://x' })
    assert_equal '/env/state.json', cfg.state_path
  end

  def test_state_path_default
    path = write_yml(VALID_YML)
    cfg  = StackWatch::Config.load(path: path, env: { 'STACKWATCH_SLACK_WEBHOOK' => 'https://x' })
    assert_equal 'state.json', cfg.state_path
  end

  def test_invalid_tier_raises
    path = write_yml(<<~YAML)
      notifications:
        slack:
          webhook_url: https://x
      packages:
        - name: foo
          ecosystem: PyPI
          tier: ultra-critical
    YAML
    assert_raises(StackWatch::ConfigError) { StackWatch::Config.load(path: path, env: {}) }
  end

  def test_missing_name_raises
    path = write_yml(<<~YAML)
      notifications:
        slack:
          webhook_url: https://x
      packages:
        - ecosystem: PyPI
    YAML
    assert_raises(StackWatch::ConfigError) { StackWatch::Config.load(path: path, env: {}) }
  end

  def test_missing_ecosystem_raises
    path = write_yml(<<~YAML)
      notifications:
        slack:
          webhook_url: https://x
      packages:
        - name: django
    YAML
    assert_raises(StackWatch::ConfigError) { StackWatch::Config.load(path: path, env: {}) }
  end

  def test_missing_slack_is_allowed
    path = write_yml("packages: []\n")
    cfg = StackWatch::Config.load(path: path, env: {})
    assert_nil cfg.slack_webhook_url
  end

  def test_unresolved_variable_in_webhook_raises
    path = write_yml(<<~YAML)
      notifications:
        slack:
          webhook_url: "${STACKWATCH_SLACK_WEBHOOK}"
      packages: []
    YAML
    err = assert_raises(StackWatch::ConfigError) { StackWatch::Config.load(path: path, env: {}) }
    assert_match 'unresolved variable', err.message
  end

  def test_invalid_webhook_url_raises
    path = write_yml(<<~YAML)
      notifications:
        slack:
          webhook_url: "not a valid url %%"
      packages: []
    YAML
    err = assert_raises(StackWatch::ConfigError) { StackWatch::Config.load(path: path, env: {}) }
    assert_match 'Invalid Slack webhook URL', err.message
  end

  def test_file_not_found_raises
    assert_raises(StackWatch::ConfigError) do
      StackWatch::Config.load(path: '/nonexistent/stack.yml', env: {})
    end
  end

  def test_max_age_days_defaults_to_30
    path = write_yml(VALID_YML)
    cfg  = StackWatch::Config.load(path: path, env: {})
    assert_equal 30, cfg.max_age_days
  end

  def test_max_age_days_override
    path = write_yml(<<~YAML)
      filters:
        max_age_days: 7
      packages: []
    YAML
    cfg = StackWatch::Config.load(path: path, env: {})
    assert_equal 7, cfg.max_age_days
  end

  def test_max_age_days_disabled_with_false
    path = write_yml(<<~YAML)
      filters:
        max_age_days: false
      packages: []
    YAML
    cfg = StackWatch::Config.load(path: path, env: {})
    assert_nil cfg.max_age_days
  end

  def test_max_age_days_invalid_raises
    path = write_yml(<<~YAML)
      filters:
        max_age_days: "thirty"
      packages: []
    YAML
    assert_raises(StackWatch::ConfigError) { StackWatch::Config.load(path: path, env: {}) }
  end

  def test_package_version_is_parsed_and_optional
    path = write_yml(<<~YAML)
      packages:
        - name: rails
          ecosystem: RubyGems
          version: 8.0.5
        - name: nokogiri
          ecosystem: RubyGems
    YAML
    cfg = StackWatch::Config.load(path: path, env: {})
    assert_equal '8.0.5', cfg.packages[0].version
    assert_nil cfg.packages[1].version
  end

  def test_cvss_thresholds_default
    cfg = StackWatch::Config.load(path: write_yml(VALID_YML), env: {})
    assert_in_delta 4.0, cfg.drop_below_cvss, 0.001
    assert_in_delta 7.0, cfg.digest_below_cvss, 0.001
  end

  def test_cvss_thresholds_override
    path = write_yml(<<~YAML)
      filters:
        drop_below_cvss: 2.5
        digest_below_cvss: 8
      packages: []
    YAML
    cfg = StackWatch::Config.load(path: path, env: {})
    assert_in_delta 2.5, cfg.drop_below_cvss, 0.001
    assert_in_delta 8.0, cfg.digest_below_cvss, 0.001
  end

  def test_drop_above_digest_raises
    path = write_yml(<<~YAML)
      filters:
        drop_below_cvss: 8
        digest_below_cvss: 5
      packages: []
    YAML
    assert_raises(StackWatch::ConfigError) { StackWatch::Config.load(path: path, env: {}) }
  end

  def test_cvss_threshold_out_of_range_raises
    path = write_yml(<<~YAML)
      filters:
        digest_below_cvss: 42
      packages: []
    YAML
    assert_raises(StackWatch::ConfigError) { StackWatch::Config.load(path: path, env: {}) }
  end
end
