module StackWatch
  Package = Struct.new(:name, :ecosystem, :tier, :version, keyword_init: true) do
    VALID_TIERS = %w[critical standard].freeze

    def critical?
      tier == 'critical'
    end

    def validate!
      raise ConfigError, "Package missing 'name'"      if name.nil? || name.strip.empty?
      raise ConfigError, "Package missing 'ecosystem'" if ecosystem.nil? || ecosystem.strip.empty?
      raise ConfigError, "Invalid tier '#{tier}' for #{name}" unless VALID_TIERS.include?(tier)

      self
    end
  end

  AppConfig = Struct.new(:packages, :slack_webhook_url, :state_path,
                         :max_age_days, :drop_below_cvss, :digest_below_cvss,
                         keyword_init: true)

  class Config
    DEFAULT_STATE_PATH     = 'state.json'
    DEFAULT_TIER           = 'standard'
    DEFAULT_MAX_AGE_DAYS   = 30
    DEFAULT_DROP_BELOW     = 4.0 # CVSS < this -> dropped entirely
    DEFAULT_DIGEST_BELOW   = 7.0 # drop_below <= CVSS < this -> weekly digest, no @here

    def self.load(path: 'stack.yml', state_path_override: nil, env: ENV)
      new(path: path, state_path_override: state_path_override, env: env).parse
    end

    def initialize(path:, state_path_override:, env:)
      @path                = path
      @state_path_override = state_path_override
      @env                 = env
    end

    def parse
      raise ConfigError, "Config file not found: #{@path}" unless File.exist?(@path)

      raw = Psych.safe_load_file(@path, symbolize_names: false)
      raise ConfigError, 'stack.yml must be a YAML mapping' unless raw.is_a?(Hash)

      drop_below   = parse_cvss_threshold(raw, 'drop_below_cvss', DEFAULT_DROP_BELOW)
      digest_below = parse_cvss_threshold(raw, 'digest_below_cvss', DEFAULT_DIGEST_BELOW)
      if drop_below > digest_below
        raise ConfigError,
              "filters.drop_below_cvss (#{drop_below}) must be <= filters.digest_below_cvss (#{digest_below})"
      end

      AppConfig.new(
        packages: parse_packages(raw.fetch('packages', [])),
        slack_webhook_url: resolve_slack_webhook(raw),
        state_path: resolve_state_path(raw),
        max_age_days: parse_max_age_days(raw),
        drop_below_cvss: drop_below,
        digest_below_cvss: digest_below
      )
    end

    private

    def parse_cvss_threshold(raw, key, default)
      value = raw.dig('filters', key)
      return default if value.nil?

      unless value.is_a?(Numeric) && value >= 0 && value <= 10
        raise ConfigError, "filters.#{key} must be a number between 0 and 10, got: #{value.inspect}"
      end

      value.to_f
    end

    def parse_max_age_days(raw)
      value = raw.dig('filters', 'max_age_days')
      return DEFAULT_MAX_AGE_DAYS if value.nil?
      return nil if value == false

      unless value.is_a?(Integer) && value >= 0
        raise ConfigError, "filters.max_age_days must be a non-negative integer or false, got: #{value.inspect}"
      end

      value
    end

    def parse_packages(raw_list)
      raise ConfigError, "'packages' must be a list" unless raw_list.is_a?(Array)

      raw_list.map do |entry|
        raise ConfigError, 'Each package entry must be a mapping' unless entry.is_a?(Hash)

        version = entry['version']
        Package.new(
          name: entry['name'].to_s,
          ecosystem: entry['ecosystem'].to_s,
          tier: entry.fetch('tier', DEFAULT_TIER),
          version: version.nil? ? nil : version.to_s
        ).validate!
      end
    end

    def resolve_slack_webhook(raw)
      url = @env['STACKWATCH_SLACK_WEBHOOK'] ||
            raw.dig('notifications', 'slack', 'webhook_url')
      return nil if url.nil? || url.strip.empty?

      if url.include?('${')
        raise ConfigError,
              "Slack webhook URL contains unresolved variable: #{url}. Set STACKWATCH_SLACK_WEBHOOK env var."
      end

      URI(url)
      url
    rescue URI::InvalidURIError
      raise ConfigError, "Invalid Slack webhook URL: #{url}"
    end

    def resolve_state_path(raw)
      @state_path_override ||
        @env['STACKWATCH_STATE_PATH'] ||
        raw.fetch('state_path', DEFAULT_STATE_PATH)
    end
  end
end
