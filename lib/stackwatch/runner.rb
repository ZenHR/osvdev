module StackWatch
  class Runner
    DEFAULT_DROP_BELOW   = 4.0
    DEFAULT_DIGEST_BELOW = 7.0
    # A CVE id this many years older than its publish date is a retroactive backfill
    # (old fix, new number) -> digest, never page. ponytail: hardcoded; lift to a
    # filters.backfill_gap_years config knob if it ever needs per-deploy tuning.
    BACKFILL_GAP_YEARS = 2

    def self.call(config, stdout: $stdout, stderr: $stderr, source: nil, notifier: nil)
      new(config, stdout: stdout, stderr: stderr, source: source, notifier: notifier).run
    end

    def initialize(config, stdout:, stderr:, source: nil, notifier: nil)
      @config   = config
      @stdout   = stdout
      @stderr   = stderr
      @state    = State.load(config.state_path)
      @source   = source || Sources::OSV.new(config.packages)
      @notifier = notifier || (config.slack_webhook_url ? Notifiers::Slack.new(config.slack_webhook_url) : nil)
    end

    def run
      stubs_by_package = @source.fetch_all
      cutoff       = age_cutoff
      errors       = []
      seen_aliases = Set.new # cross-package/alias dedup within this run
      digest       = []
      alerts       = [] # sent in batches after the scan, not one message per CVE

      stubs_by_package.each do |package, stubs|
        @state.diff(package, stubs).each do |stub|
          vuln = enrich(stub)
          next if vuln.nil? # enrichment failed -> leave unseen, retry next run

          # Marked seen once successfully processed (even if dropped/filtered below),
          # so we never re-fetch the full record for it again.
          # ponytail: "considered == seen". Trade-off: widening max_age_days later
          # won't resurface already-seen old vulns — clear state.json to force a rescan.
          @state.mark_seen(package, [stub])

          next if vuln.withdrawn?
          next if cutoff && vuln.older_than?(cutoff)
          next if vuln.alias_ids.any? { |a| seen_aliases.include?(a) }

          vuln.alias_ids.each { |a| seen_aliases << a }

          if vuln.backfill?(BACKFILL_GAP_YEARS)
            digest << { package: package, vuln: vuln }
            @stdout.puts "  [digest/backfill] #{vuln.id} #{package.ecosystem}/#{package.name}"
            next
          end

          case route(vuln)
          when :drop
            @stdout.puts "  [drop]  #{vuln.id} #{package.ecosystem}/#{package.name} (CVSS #{score_str(vuln)})"
          when :digest
            digest << { package: package, vuln: vuln }
            @stdout.puts "  [digest] #{vuln.id} #{package.ecosystem}/#{package.name} (CVSS #{score_str(vuln)})"
          when :alert
            mention = mention?(vuln)
            alerts << { package: package, vuln: vuln, mention: mention }
            @stdout.puts "  [alert#{mention ? '+@here' : ''}] #{vuln.id} #{package.ecosystem}/#{package.name}"
          end
        end
      end

      @state.persist

      begin
        @notifier&.post_alerts(alerts) if alerts.any?
      rescue Notifiers::SlackError => e
        errors << e
        @stderr.puts "WARN: Slack alerts failed: #{e.message}"
      end
      begin
        @notifier&.post_digest(digest) if digest.any?
      rescue Notifiers::SlackError => e
        @stderr.puts "WARN: Slack digest failed: #{e.message}"
      end
      begin
        @notifier&.post_summary(alerts.size, digest_count: digest.size)
      rescue StandardError
        nil
      end

      @stdout.puts "StackWatch: #{alerts.size} alert#{alerts.size == 1 ? '' : 's'}, #{digest.size} digested."
      raise errors.first if errors.any?

      alerts.size
    end

    private

    def enrich(stub)
      @source.fetch_vuln(stub.id)
    rescue Sources::OSVError => e
      @stderr.puts "WARN: enrichment failed for #{stub.id}: #{e.message}"
      nil
    end

    def route(vuln)
      score = vuln.severity_score
      return :digest if score.nil? # unknown severity -> digest, never @here
      return :drop   if score < drop_below
      return :digest if score < digest_below

      :alert
    end

    # @here only when it's actionable: high severity AND a patch actually exists.
    def mention?(vuln)
      score = vuln.severity_score
      !score.nil? && score >= digest_below && vuln.patch_available?
    end

    def drop_below
      @config.drop_below_cvss || DEFAULT_DROP_BELOW
    end

    def digest_below
      @config.digest_below_cvss || DEFAULT_DIGEST_BELOW
    end

    def score_str(vuln)
      vuln.severity_score ? format('%.1f', vuln.severity_score) : vuln.cvss_score
    end

    def age_cutoff
      days = @config.max_age_days
      return nil if days.nil?

      Time.now.utc - (days * 86_400)
    end
  end
end
