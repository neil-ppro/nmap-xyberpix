local http = require "http"
local http_offsec = require "http_offsec"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Sends a minimal GraphQL introspection query over HTTP POST to common endpoint
paths. If introspection is enabled, summarizes query/mutation/subscription
types and flags type names suggesting users, roles, files, or secrets.

Authorized testing only.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local INTROSPECTION_BODY = '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"}'

local ENDPOINTS = http_offsec.graphql_default_paths()

local RISKY = {"password", "token", "secret", "user", "role", "admin", "file", "upload", "delete", "exec"}

local function flag_types(types)
  local hits = {}
  if type(types) ~= "table" then
    return hits
  end
  for _, t in ipairs(types) do
    if type(t) == "table" and type(t.name) == "string" then
      local n = string.lower(t.name)
      for _, w in ipairs(RISKY) do
        if string.find(n, w, 1, true) then
          hits[#hits + 1] = t.name
          break
        end
      end
    end
  end
  return hits
end

action = function(host, port)
  local base = stdnse.get_script_args(SCRIPT_NAME .. ".basepath") or ""
  local custom = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local paths = {}
  local perr
  if custom then
    perr = http_offsec.assert_safe_http_request_path(custom)
    if perr then
      return stdnse.format_output(false, perr)
    end
    paths[1] = custom
  else
    perr = http_offsec.assert_safe_basepath(base)
    if perr then
      return stdnse.format_output(false, perr)
    end
    for _, e in ipairs(ENDPOINTS) do
      paths[#paths + 1] = base .. e
    end
  end

  local opts = {
    header = {["Content-Type"] = "application/json"},
  }

  for _, path in ipairs(paths) do
    perr = http_offsec.assert_safe_http_request_path(path)
    if perr then
      return stdnse.format_output(false, perr)
    end
    local resp = http.post(host, port, path, opts, nil, INTROSPECTION_BODY)
    if resp and resp.body then
      local ok, doc = pcall(json.parse, resp.body)
      if ok and type(doc) == "table" and doc.data and doc.data.__schema then
        local schema = doc.data.__schema
        local lines = {}
        lines[#lines + 1] = "Introspection accepted at " .. path
        if schema.queryType and schema.queryType.name then
          lines[#lines + 1] = "  queryType: " .. schema.queryType.name
        end
        if schema.mutationType and schema.mutationType.name then
          lines[#lines + 1] = "  mutationType: " .. schema.mutationType.name
        end
        if schema.subscriptionType and schema.subscriptionType.name then
          lines[#lines + 1] = "  subscriptionType: " .. schema.subscriptionType.name
        end
        local types = schema.types
        local ntypes = type(types) == "table" and #types or 0
        lines[#lines + 1] = ("  types: %d"):format(ntypes)
        local risky = flag_types(types)
        if #risky > 0 then
          lines[#lines + 1] = "  noteworthy type names:"
          for i = 1, math.min(20, #risky) do
            lines[#lines + 1] = "    " .. risky[i]
          end
        end
        return stdnse.format_output(true, lines)
      end
    end
  end
  return stdnse.format_output(false, "No GraphQL introspection response on common paths.")
end
