module StackWatch
  # Turns an OSV vuln record's severity into a numeric CVSS base score (0.0-10.0),
  # so alerts can be routed by threshold instead of a static per-package tier.
  #
  # Order of preference: a parseable CVSS v3.x vector, then any bare numeric score,
  # then the qualitative `database_specific.severity` label. Returns nil when severity
  # is genuinely unknown (caller should treat nil conservatively — digest, never @here).
  #
  # ponytail: implements the CVSS v3.0/3.1 base-score formula only. v4.0 vectors are
  # scored via the qualitative label fallback; add a v4 lookup-table scorer if osv
  # starts shipping v4-only records. Base metrics only (no temporal/environmental).
  module Severity
    QUALITATIVE = { 'CRITICAL' => 9.5, 'HIGH' => 8.0, 'MODERATE' => 5.5,
                    'MEDIUM' => 5.5, 'LOW' => 2.0 }.freeze

    AV   = { 'N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2 }.freeze
    AC   = { 'L' => 0.77, 'H' => 0.44 }.freeze
    UI   = { 'N' => 0.85, 'R' => 0.62 }.freeze
    PR_U = { 'N' => 0.85, 'L' => 0.62, 'H' => 0.27 }.freeze # scope unchanged
    PR_C = { 'N' => 0.85, 'L' => 0.68, 'H' => 0.5 }.freeze  # scope changed
    CIA  = { 'H' => 0.56, 'L' => 0.22, 'N' => 0.0 }.freeze

    module_function

    def score(raw)
      severities = raw['severity'] || []

      v3 = severities.find { |s| s['type'].to_s.start_with?('CVSS_V3') }&.dig('score')
      from_vector = parse_vector(v3)
      return from_vector if from_vector

      numeric = severities.map { |s| s['score'] }.find { |x| numeric?(x) } ||
                raw.dig('database_specific', 'cvss', 'score')
      return Float(numeric) if numeric?(numeric)

      QUALITATIVE[raw.dig('database_specific', 'severity').to_s.upcase]
    end

    # Parse a CVSS v3.x vector string (or accept a bare number) -> Float base score, else nil.
    def parse_vector(vector)
      return Float(vector) if numeric?(vector)
      return nil unless vector.is_a?(String) && vector.start_with?('CVSS:3')

      m = vector.split('/').each_with_object({}) do |part, h|
        k, v = part.split(':', 2)
        h[k] = v
      end
      return nil unless %w[AV AC PR UI S C I A].all? { |k| m.key?(k) }

      scope_changed = m['S'] == 'C'
      pr = (scope_changed ? PR_C : PR_U)[m['PR']]
      metrics = [AV[m['AV']], AC[m['AC']], pr, UI[m['UI']], CIA[m['C']], CIA[m['I']], CIA[m['A']]]
      return nil if metrics.any?(&:nil?)

      iss = 1 - ((1 - CIA[m['C']]) * (1 - CIA[m['I']]) * (1 - CIA[m['A']]))
      impact = if scope_changed
                 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02)**15)
               else
                 6.42 * iss
               end
      return 0.0 if impact <= 0

      exploitability = 8.22 * AV[m['AV']] * AC[m['AC']] * pr * UI[m['UI']]
      total = impact + exploitability
      total *= 1.08 if scope_changed
      roundup([total, 10.0].min)
    end

    # CVSS 3.1 round-up to one decimal. round(5) first to shed float dust so a true
    # X.0 doesn't get bumped to X.1.
    def roundup(value)
      (value * 10).round(5).ceil / 10.0
    end

    def numeric?(value)
      Float(value)
      true
    rescue ArgumentError, TypeError
      false
    end
  end
end
