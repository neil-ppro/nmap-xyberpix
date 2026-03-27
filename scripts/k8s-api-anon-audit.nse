local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts unauthenticated read of Kubernetes API discovery endpoints (/version,
/api, /api/v1/namespaces) on common TLS ports. A 200 with JSON does not prove
misconfiguration until RBAC is reviewed, but anonymous access is worth flagging.

Use only on clusters you are authorized to assess.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = function(host, port)
  if port.protocol ~= "tcp" then
    return false
  end
  if port.number == 6443 or port.number == 8443 or port.number == 8001 then
    return true
  end
  return shortport.ssl(host, port) or shortport.http(host, port)
end

local PATHS = {"/version", "/api", "/api/v1/namespaces"}

action = function(host, port)
  local lines = {}
  for _, p in ipairs(PATHS) do
    local resp = http.get(host, port, p)
    if resp and resp.status == 200 and resp.body and #resp.body > 2 then
      local ok, doc = pcall(json.parse, resp.body)
      local kind = ok and type(doc) == "table" and (doc.kind or doc.major) or nil
      lines[#lines + 1] = ("%s -> 200 JSON (%s)"):format(
        p,
        kind and ("kind/major=" .. tostring(kind)) or "unparsed"
      )
    elseif resp and resp.status then
      lines[#lines + 1] = ("%s -> %s"):format(p, tostring(resp.status))
    end
  end
  if #lines == 0 then
    return stdnse.format_output(false, "No HTTP response from Kubernetes-style paths.")
  end
  return stdnse.format_output(true, lines)
end
