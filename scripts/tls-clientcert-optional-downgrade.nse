local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
On TLS-wrapped HTTP ports, requests / and a few common paths and searches
responses for phrases often used when client certificates are optional or
rejected (e.g. \"No required SSL certificate\", \"400 No required SSL\").
A 200 OK on / without such messages does not prove absence of mTLS on other
routes - heuristic only.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.ssl

local PATHS = {"/", "/api/", "/admin"}

local CERT_HINTS = {
  "no required ssl certificate",
  "ssl certificate",
  "client certificate",
  "bad certificate",
  "peer does not provide",
  "mutual tls",
  "mtls",
}

action = function(host, port)
  local lines = {}
  for _, p in ipairs(PATHS) do
    local resp = http.get(host, port, p)
    if resp then
      local st = resp.status and tostring(resp.status) or "?"
      local body = string.lower(resp.body or "")
      local hints = {}
      for _, h in ipairs(CERT_HINTS) do
        if string.find(body, h, 1, true) then
          hints[#hints + 1] = h
        end
      end
      if #hints > 0 then
        lines[#lines + 1] = ("%s -> %s; body mentions: %s"):format(p, st, table.concat(hints, ", "))
      else
        lines[#lines + 1] = ("%s -> %s (no common client-cert error strings)"):format(p, st)
      end
    end
  end
  if #lines == 0 then
    return stdnse.format_output(false, "No TLS HTTP response.")
  end
  return stdnse.format_output(true, lines)
end
