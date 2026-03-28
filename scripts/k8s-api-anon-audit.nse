local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Probes Kubernetes API-style paths (/version, /api, /api/v1/namespaces). Classifies
responses: anonymous JSON (200 with expected API shapes), auth-required
(401/403), reachable non-JSON, or connection/TLS failure. Self-signed API
certificates are common; use standard Nmap SSL options if requests fail.

Use only on clusters you are authorized to assess.
]]

author = "nmap-xyberpix"
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

local function classify(path, resp)
  if not resp then
    return "no_response", "no HTTP response (TLS verify, timeout, or non-HTTP service)"
  end
  local st = resp.status and tonumber(resp.status) or 0
  local wa = resp.header and (resp.header["www-authenticate"] or resp.header["WWW-Authenticate"] or "")
  local body = resp.body or ""
  if st == 401 or st == 403 then
    return "auth_required", ("HTTP %d%s"):format(
      st,
      wa ~= "" and (" WWW-Authenticate: " .. wa) or ""
    )
  end
  if st == 200 and #body > 2 then
    local ok, doc = pcall(json.parse, body)
    if ok and type(doc) == "table" then
      if path == "/version" and (doc.major or doc.gitVersion or doc.minor) then
        return "anonymous_json", "version JSON without credentials (check RBAC; major=" .. tostring(doc.major or "?") .. ")"
      end
      if path == "/api" and doc.kind == "APIVersions" then
        return "anonymous_json", "APIVersions discovery JSON returned (anonymous read of /api)"
      end
      if path == "/api/v1/namespaces" and doc.kind == "NamespaceList" and type(doc.items) == "table" then
        return "anonymous_json", ("NamespaceList returned %d items (critical if unauthenticated)"):format(#doc.items)
      end
      if doc.kind then
        return "json_other", "HTTP 200 JSON kind=" .. tostring(doc.kind)
      end
      return "json_unparsed", "HTTP 200 JSON (unparsed shape)"
    end
    return "reachable_non_json", ("HTTP 200 non-JSON body len=%d"):format(#body)
  end
  return "other", ("HTTP %s body_len=%d"):format(tostring(resp.status or "?"), #body)
end

action = function(host, port)
  local out = stdnse.output_table()
  local summary = {}
  local has_anon = false
  local has_auth = false
  local has_fail = false

  for _, p in ipairs(PATHS) do
    local resp = http.get(host, port, p)
    local cls, detail = classify(p, resp)
    out[p] = cls .. ": " .. detail
    summary[#summary + 1] = p .. " -> " .. cls
    if cls == "anonymous_json" then
      has_anon = true
    elseif cls == "auth_required" then
      has_auth = true
    elseif cls == "no_response" then
      has_fail = true
    end
  end

  if has_anon then
    out.summary = "API reachable with JSON that looks like unauthenticated Kubernetes discovery - verify RBAC immediately."
  elseif has_auth and not has_anon then
    out.summary = "API likely reachable but returned 401/403 (auth required) - not anonymous disclosure from these paths."
  elseif has_fail then
    out.summary = "Some requests failed (TLS/connection). Retry with -d or ssl script-args if this is a known kube-apiserver."
  else
    out.summary = "No anonymous Kubernetes JSON pattern matched; review per-path lines."
  end

  return out
end
