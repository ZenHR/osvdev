module StackWatch
  module Notifiers
    class Slack
      TIMEOUT_SEC      = 10
      ALERT_BATCH_SIZE = 10 # max advisories per alert message, keeps posts readable

      def initialize(webhook_url)
        @uri = URI(webhook_url)
      end

      # Batched alerts: up to ALERT_BATCH_SIZE high-severity advisories per Slack
      # message instead of one message per CVE. Each item is
      # { package:, vuln:, mention: }; mention (high severity + patch available) is
      # decided by the Runner. @here is applied once per batch if any item warrants it.
      def post_alerts(items)
        return if items.empty?

        items.each_slice(ALERT_BATCH_SIZE) do |batch|
          head   = batch.any? { |i| i[:mention] } ? '<!here> ' : ''
          intro  = "#{head}:rotating_light: StackWatch — #{batch.size} high-severity " \
                   "advisor#{batch.size == 1 ? 'y' : 'ies'}"
          blocks = batch.map { |i| format_alert(package: i[:package], vuln: i[:vuln]) }
          post('text' => ([intro] + blocks).join("\n\n"))
        end
      end

      # One grouped message for lower-severity advisories — no @here.
      def post_digest(items)
        return if items.empty?

        lines = items.map do |item|
          v = item[:vuln]
          p = item[:package]
          "• *#{p.ecosystem}/#{p.name}* #{advisory_label(v)} #{v.id} " \
            "(CVSS #{score_str(v)}, #{patch_short(v)}) <#{v.url}|osv>"
        end
        header = ":mag: StackWatch digest — #{items.size} lower-severity " \
                 "advisor#{items.size == 1 ? 'y' : 'ies'} (review, no page)"
        post('text' => ([header] + lines).join("\n"))
      end

      def post_summary(alerted, digest_count: 0)
        emoji = alerted.zero? ? ':white_check_mark:' : ':rotating_light:'
        post('text' => "#{emoji} StackWatch: #{alerted} alert#{alerted == 1 ? '' : 's'}, " \
                       "#{digest_count} digested.")
      end

      private

      # One advisory block within a batched alert message (batch carries the @here).
      def format_alert(package:, vuln:)
        patch = vuln.patch_available? ? "Patched in *#{vuln.fixed}* — upgrade" : 'no patch yet — monitor'

        [
          "#{advisory_label(vuln)} for *#{package.name}* " \
            "(#{package.ecosystem}) — CVSS #{score_str(vuln)}",
          "*#{vuln.id}*#{alias_suffix(vuln)}",
          vuln.summary.to_s.empty? ? '(no summary)' : vuln.summary,
          "Affected: #{vuln.affected}   #{patch}",
          "<#{vuln.url}|View on osv.dev>"
        ].join("\n")
      end

      # osv returns GHSA-/PYSEC-/CVE- ids; label honestly instead of always "CVE".
      def advisory_label(vuln)
        vuln.id.to_s.start_with?('CVE-') ? 'CVE' : (vuln.id.to_s.split('-').first || 'Advisory')
      end

      def alias_suffix(vuln)
        others = Array(vuln.aliases)
        others.empty? ? '' : " (#{others.join(', ')})"
      end

      def patch_short(vuln)
        vuln.patch_available? ? "patch #{vuln.fixed}" : 'no patch'
      end

      # Prefer the numeric base score; fall back to the raw display string.
      def score_str(vuln)
        vuln.severity_score ? format('%.1f', vuln.severity_score) : vuln.cvss_score
      end

      def post(payload)
        http = Net::HTTP.new(@uri.host, @uri.port)
        http.use_ssl      = (@uri.scheme == 'https')
        http.open_timeout = TIMEOUT_SEC
        http.read_timeout = TIMEOUT_SEC

        req = Net::HTTP::Post.new(@uri.request_uri)
        req['Content-Type'] = 'application/json'
        req.body = JSON.generate(payload)

        res = http.request(req)
        raise SlackError, "Slack webhook error #{res.code}: #{res.body}" unless res.is_a?(Net::HTTPSuccess)

        true
      rescue Net::OpenTimeout, Net::ReadTimeout => e
        raise SlackError, "Slack webhook timeout: #{e.message}"
      end
    end
  end
end
