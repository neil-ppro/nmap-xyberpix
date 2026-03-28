local http = require "http"
local http_offsec = require "http_offsec"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Builds request paths by substituting the literal substring CANARY in
http-ssrf-canary.template with each test URL (URL-encoded). Compares HTTP
status and response body length - useful when an app fetches user-supplied
URLs.

Requires http-ssrf-canary.unsafe=1 (and legal authorization). One request per
canary URL by default.

Example: --script-args 'http-ssrf-canary.template=/fetch?u=CANARY,http-ssrf-canary.unsafe=1'

Intrusive: may trigger outbound fetches from the application.
]]

author = "nmap-xyberpix"
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
      "Set http-ssrf-canary.template=/path?param=CANARY (literal CANARY substring required)."
    )
  end

  local terr = http_offsec.assert_safe_http_request_path(template)
  if terr then
    return stdnse.format_output(false, terr)
  end

  local CANARIES = http_offsec.ssrf_canaries()
  local results = {}
  for _, c in ipairs(CANARIES) do
    local enc = url.escape(c.url)
    local path = http_offsec.substitute_canary(template, enc)
    local perr = http_offsec.assert_safe_http_request_path(path)
    if perr then
      return stdnse.format_output(false, perr)
    end
    local resp = http.get(host, port, path)
    local st = resp and resp.status and tostring(resp.status) or "?"
    local blen = (resp and resp.body and #resp.body) or 0
    results[#results + 1] = ("%s: status=%s body_len=%d"):format(c.name, st, blen)
  end
  results[#results + 1] = "Interpret differences manually; SSRF is not confirmed by this script alone."
  return stdnse.format_output(true, results)
end
