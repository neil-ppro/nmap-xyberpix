local http = require "http"
local shortport = require "shortport"
local url = require "url"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Builds request paths by substituting the literal substring CANARY in
http-ssrf-canary.template with each test URL (URL-encoded). Compares HTTP
status and response body length - useful when an app fetches user-supplied
URLs. Operator must supply template (e.g. /proxy?url=CANARY).

Example: --script-args 'http-ssrf-canary.template=/fetch?u=CANARY'

Intrusive: generates traffic that may trigger outbound fetches from the app.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.http

local CANARIES = {
  {name = "loopback", url = "http://127.0.0.1/"},
  {name = "metadata", url = "http://169.254.169.254/latest/meta-data/"},
  {name = "localhost_name", url = "http://localhost/"},
}

action = function(host, port)
  local template = stdnse.get_script_args(SCRIPT_NAME .. ".template")
  if not template or not string.find(template, "CANARY", 1, true) then
    return stdnse.format_output(
      false,
      "Set http-ssrf-canary.template=/path?param=CANARY (literal CANARY substring required)."
    )
  end

  local results = {}
  for _, c in ipairs(CANARIES) do
    local enc = url.escape(c.url)
    local path = string.gsub(template, "CANARY", enc, 1)
    local resp = http.get(host, port, path)
    local st = resp and resp.status and tostring(resp.status) or "?"
    local blen = (resp and resp.body and #resp.body) or 0
    results[#results + 1] = ("%s: status=%s body_len=%d"):format(c.name, st, blen)
  end
  results[#results + 1] = "Interpret differences manually; SSRF is not confirmed by this script alone."
  return stdnse.format_output(true, results)
end
