$LOAD_PATH.unshift File.expand_path('../lib', __dir__)

require 'minitest/autorun'
require 'minitest/reporters'
require 'webmock/minitest'
require 'stackwatch'
require 'stackwatch/config'
require 'stackwatch/vuln'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

WebMock.disable_net_connect!

def fixture(name)
  File.read(File.expand_path("fixtures/#{name}", __dir__))
end

def fixture_path(name)
  File.expand_path("fixtures/#{name}", __dir__)
end

def stub_vuln(id: 'CVE-STUB', summary: '', cvss_score: 'N/A', severity_score: :auto,
              affected: 'unknown', fixed: nil, url: nil, published: nil, withdrawn: nil,
              aliases: [])
  score = if severity_score == :auto
            begin
              Float(cvss_score)
            rescue ArgumentError, TypeError
              nil
            end
          else
            severity_score
          end
  StackWatch::Vuln.new(
    id: id, summary: summary, cvss_score: cvss_score, severity_score: score,
    affected: affected, fixed: fixed,
    url: url || "https://osv.dev/vulnerability/#{id}",
    published: published, withdrawn: withdrawn, aliases: aliases
  )
end
