require 'json'
require 'net/http'
require 'psych'
require 'set'
require 'time'

module StackWatch
  VERSION = '0.1.0'

  class ConfigError < StandardError; end

  module Sources
    class OSVError < StandardError; end
  end

  module Notifiers
    class SlackError < StandardError; end
  end

  # Lightweight result of a querybatch call. osv.dev's /v1/querybatch returns only
  # { id, modified } per vuln — no severity/affected/fixed/published. The full record
  # is fetched on demand (Sources::OSV#fetch_vuln) only for unseen ids.
  Stub = Struct.new(:id, :modified, keyword_init: true)

  autoload :Config,   'stackwatch/config'
  autoload :State,    'stackwatch/state'
  autoload :Vuln,     'stackwatch/vuln'
  autoload :Severity, 'stackwatch/severity'
  autoload :Runner,   'stackwatch/runner'
  autoload :CLI,      'stackwatch/cli'

  module Sources
    autoload :OSV, 'stackwatch/sources/osv'
  end

  module Notifiers
    autoload :Slack, 'stackwatch/notifiers/slack'
  end
end
