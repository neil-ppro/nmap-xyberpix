local http = require "http"
local http_offsec = require "http_offsec"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Fetches OAuth 2.0 / OpenID Provider metadata from well-known URLs and flags
common risky patterns: token_endpoint_auth_methods_supported including
\"none\" for confidential clients context, unsupported https issuer mismatches
(string compare only), response_types_supported including \"token\" (implicit),
and missing https on endpoints when issuer is https.

Heuristic only - manual review required.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local WELL_KNOWN = {
  "/.well-known/openid-configuration",
  "/.well-known/oauth-authorization-server",
}

local function check_doc(doc, url)
  if type(doc) ~= "table" then
    return nil
  end
  local lines = { "Metadata: " .. url }
  local issuer = doc.issuer
  if issuer and string.sub(issuer, 1, 8) ~= "https://" then
    lines[#lines + 1] = "NOTE: issuer does not start with https://"
  end
  local rts = doc.response_types_supported
  if type(rts) == "table" then
    for _, rt in ipairs(rts) do
      if rt == "token" or rt == "id_token token" then
        lines[#lines + 1] = "NOTE: response_types_supported includes implicit-style: " .. tostring(rt)
        break
      end
    end
  end
  local am = doc.token_endpoint_auth_methods_supported
  if type(am) == "table" then
    for _, m in ipairs(am) do
      if m == "none" then
        lines[#lines + 1] = "NOTE: token_endpoint_auth_methods_supported includes \"none\"."
        break
      end
    end
  end
  local authz = doc.authorization_endpoint
  local tok = doc.token_endpoint
  if issuer and type(authz) == "string" and string.sub(authz, 1, 8) == "http://" and string.sub(issuer, 1, 8) == "https://" then
    lines[#lines + 1] = "NOTE: authorization_endpoint is http while issuer is https."
  end
  if issuer and type(tok) == "string" and string.sub(tok, 1, 8) == "http://" and string.sub(issuer, 1, 8) == "https://" then
    lines[#lines + 1] = "NOTE: token_endpoint is http while issuer is https."
  end
  if #lines > 1 then
    return lines
  end
  lines[#lines + 1] = "No obvious misconfiguration flags (still review manually)."
  return lines
end

action = function(host, port)
  local base = stdnse.get_script_args(SCRIPT_NAME .. ".basepath") or ""
  local err = http_offsec.assert_safe_basepath(base)
  if err then
    return stdnse.format_output(false, err)
  end
  for _, wk in ipairs(WELL_KNOWN) do
    local path = base .. wk
    err = http_offsec.assert_safe_http_request_path(path)
    if err then
      return stdnse.format_output(false, err)
    end
    local resp = http.get(host, port, path)
    if resp and resp.status == 200 and resp.body then
      local ok, doc = pcall(json.parse, resp.body)
      if ok and type(doc) == "table" then
        return stdnse.format_output(true, check_doc(doc, path))
      end
    end
  end
  return stdnse.format_output(false, "No OAuth/OIDC well-known JSON found at standard paths.")
end
