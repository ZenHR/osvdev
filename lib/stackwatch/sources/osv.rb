module StackWatch
  module Sources
    class OSV
      BATCH_URI   = URI('https://api.osv.dev/v1/querybatch')
      VULN_URL    = 'https://api.osv.dev/v1/vulns/' # + id
      TIMEOUT_SEC = 15

      def initialize(packages)
        @packages = packages
      end

      # Cheap: one batch call. Returns { Package => [Stub(id, modified)] }.
      # querybatch returns only ids (+ modified) — it does NOT include severity,
      # affected, fixed or published. Enrichment is deferred to #fetch_vuln so we
      # only pay for the full record on ids we haven't already reported.
      def fetch_all
        return {} if @packages.empty?

        parse_batch(post_json(BATCH_URI, build_payload))
      end

      # Fetch the full, enriched record for a single vuln id. Returns a Vuln.
      def fetch_vuln(id)
        Vuln.from_osv(get_json("#{VULN_URL}#{id}"))
      end

      private

      def build_payload
        queries = @packages.map do |pkg|
          query = { 'package' => { 'name' => pkg.name, 'ecosystem' => pkg.ecosystem } }
          # When a version is pinned, osv.dev filters server-side to vulns that
          # actually affect that version — the single biggest noise reducer.
          version = pkg.respond_to?(:version) ? pkg.version : nil
          query['version'] = version.to_s if version && !version.to_s.strip.empty?
          query
        end
        { 'queries' => queries }
      end

      def parse_batch(body)
        results = body.fetch('results', [])
        @packages.zip(results).each_with_object({}) do |(pkg, result), map|
          vulns = result&.fetch('vulns', []) || []
          map[pkg] = vulns.map { |v| Stub.new(id: v['id'], modified: v['modified']) }
        end
      end

      def post_json(uri, payload)
        req = Net::HTTP::Post.new(uri.path)
        req['Content-Type'] = 'application/json'
        req.body = JSON.generate(payload)
        request(uri, req)
      end

      def get_json(url)
        uri = URI(url)
        request(uri, Net::HTTP::Get.new(uri.request_uri))
      end

      def request(uri, req)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl      = true
        http.open_timeout = TIMEOUT_SEC
        http.read_timeout = TIMEOUT_SEC

        res = http.request(req)
        raise OSVError, "OSV API error #{res.code}: #{res.body}" unless res.is_a?(Net::HTTPSuccess)

        JSON.parse(res.body)
      rescue Net::OpenTimeout, Net::ReadTimeout => e
        raise OSVError, "OSV API timeout: #{e.message}"
      rescue JSON::ParserError => e
        raise OSVError, "OSV API returned invalid JSON: #{e.message}"
      end
    end
  end
end
