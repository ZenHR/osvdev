module StackWatch
  Vuln = Struct.new(:id, :summary, :cvss_score, :severity_score, :affected, :fixed,
                    :url, :published, :withdrawn, :aliases, keyword_init: true) do
    def withdrawn?
      !withdrawn.nil?
    end

    def older_than?(cutoff)
      return false if published.nil?

      published < cutoff
    end

    def patch_available?
      !(fixed.nil? || fixed.to_s.strip.empty?)
    end

    # This vuln's id plus any upstream aliases (CVE <-> GHSA <-> PYSEC). Used to
    # dedupe one upstream advisory that surfaces under several ids/packages in a run.
    def alias_ids
      ([id] + Array(aliases)).compact.uniq
    end

    # A retroactively-assigned CVE: the CVE id's year is well before its publication
    # date (e.g. a CVE-2022-48xxx first published in 2026 — a 4-year-old fix only now
    # getting a number, as the Linux kernel CNA has been backfilling en masse). Real,
    # but not new; the Runner routes these to the digest so a backfill dump can't page
    # the channel. Age filtering can't catch them — their published date IS recent.
    def backfill?(gap_years)
      return false if published.nil?

      year = earliest_cve_year
      return false if year.nil?

      published.year - year >= gap_years
    end

    # Earliest year across the id + CVE aliases, e.g. CVE-2022-48001 -> 2022. nil if none.
    def earliest_cve_year
      alias_ids.filter_map { |i| i[/\ACVE-(\d{4})-/, 1]&.to_i }.min
    end

    class << self
      def from_osv(raw)
        id = raw['id']
        new(
          id: id,
          summary: extract_summary(raw),
          cvss_score: extract_cvss(raw),
          severity_score: Severity.score(raw),
          affected: extract_affected(raw),
          fixed: extract_fixed(raw),
          url: "https://osv.dev/vulnerability/#{id}",
          published: parse_time(raw['published']),
          withdrawn: parse_time(raw['withdrawn']),
          aliases: Array(raw['aliases'])
        )
      end

      private

      def extract_summary(raw)
        (raw['summary'] || raw['details'].to_s.slice(0, 200)).to_s.strip
      end

      def extract_cvss(raw)
        raw.dig('severity')
           &.find { |s| s['type'] == 'CVSS_V3' }
           &.dig('score') ||
          raw.dig('database_specific', 'cvss', 'score') ||
          'N/A'
      end

      def extract_affected(raw)
        events = raw.dig('affected', 0, 'ranges', 0, 'events') || []
        introduced = events.select { |e| e['introduced'] }.map { |e| ">=#{e['introduced']}" }
        introduced.empty? ? 'unknown' : introduced.join(', ')
      end

      def extract_fixed(raw)
        events = raw.dig('affected', 0, 'ranges', 0, 'events') || []
        events.find { |e| e['fixed'] }&.dig('fixed')
      end

      def parse_time(value)
        return nil if value.nil? || value.to_s.strip.empty?

        Time.iso8601(value.to_s)
      rescue ArgumentError
        nil
      end
    end
  end
end
