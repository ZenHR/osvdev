require_relative 'test_helper'
require 'stackwatch/severity'

class TestSeverity < Minitest::Test
  def score(raw)
    StackWatch::Severity.score(raw)
  end

  def test_parses_critical_v31_vector
    raw = { 'severity' => [{ 'type' => 'CVSS_V3',
                             'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }
    assert_in_delta 9.8, score(raw), 0.01
  end

  def test_parses_low_high_complexity_vector
    raw = { 'severity' => [{ 'type' => 'CVSS_V3',
                             'score' => 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N' }] }
    s = score(raw)
    assert_operator s, :>=, 4.0
    assert_operator s, :<,  7.0
  end

  def test_scope_changed_vector
    # A scope-changed vector scores higher than the same metrics unchanged.
    raw = { 'severity' => [{ 'type' => 'CVSS_V3',
                             'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N' }] }
    assert_in_delta 9.3, score(raw), 0.2
  end

  def test_accepts_bare_numeric_score
    assert_in_delta 7.5, score('severity' => [{ 'type' => 'CVSS_V3', 'score' => '7.5' }]), 0.001
  end

  def test_falls_back_to_database_specific_numeric
    assert_in_delta 6.1, score('database_specific' => { 'cvss' => { 'score' => '6.1' } }), 0.001
  end

  def test_falls_back_to_qualitative_label
    assert_equal 8.0, score('database_specific' => { 'severity' => 'HIGH' })
    assert_equal 9.5, score('database_specific' => { 'severity' => 'CRITICAL' })
  end

  def test_unknown_severity_is_nil
    assert_nil score('id' => 'CVE-X')
  end

  def test_v4_vector_falls_back_to_label
    # v4 base-score not computed; label wins.
    raw = { 'severity' => [{ 'type' => 'CVSS_V4', 'score' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N' }],
            'database_specific' => { 'severity' => 'MODERATE' } }
    assert_in_delta 5.5, score(raw), 0.001
  end
end
