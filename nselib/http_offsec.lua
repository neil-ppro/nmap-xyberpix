---
-- Shared helpers for nmap-ppro offensive-research HTTP/NSE scripts: path lists,
-- SSRF/cloud canary URL sets, and intrusive-run gating (script-args .unsafe=1).
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author nmap-ppro

local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("http_offsec", stdnse.seeall)

local MAX_HTTP_PATH = 8192

--- Default OpenAPI/Swagger documentation paths (used by http-openapi-map).
function openapi_paths()
  return {
    "/openapi.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/swagger.json",
    "/api/swagger.json",
    "/api-docs/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
  }
end

--- Substrings that flag a path as worth manual review (http-openapi-map).
function sensitive_path_keywords()
  return {
    "admin", "delete", "upload", "internal", "debug", "exec", "token",
    "password", "secret", "graphql", "swagger", "actuator", "jolokia",
  }
end

--- Default GraphQL HTTP paths (http-graphql-introspect).
function graphql_default_paths()
  return {"/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"}
end

--- SSRF canary URLs: loopback, IMDS-style, localhost name (http-ssrf-canary).
function ssrf_canaries()
  return {
    {name = "loopback", url = "http://127.0.0.1/"},
    {name = "metadata", url = "http://169.254.169.254/latest/meta-data/"},
    {name = "localhost_name", url = "http://localhost/"},
  }
end

--- Cloud metadata probe URLs (http-cloud-metadata-reach).
function cloud_metadata_targets()
  return {
    {name = "aws_imds", u = "http://169.254.169.254/latest/meta-data/"},
    {name = "gcp_meta_host", u = "http://metadata.google.internal/computeMetadata/v1/instance/id"},
    {name = "azure_imds", u = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
  }
end

---
-- Intrusive scripts must set <code>SCRIPT_NAME.unsafe=1</code> (or true) before
-- running probes that may trigger server-side fetches or noisy API calls.
-- @param script_name Full script name e.g. <code>http-ssrf-canary</code>
-- @return Error message string if blocked, or <code>nil</code> if allowed.
function intrusive_gate(script_name)
  local v = stdnse.get_script_args(script_name .. ".unsafe")
  if v == "1" or v == "true" or v == true then
    return nil
  end
  return ('%s is intrusive; pass --script-args \'%s.unsafe=1\' after legal authorization.'):format(
    script_name, script_name)
end

---
-- Substitute the first occurrence of the literal substring CANARY in
-- <code>template</code> with <code>encoded_value</code> (caller URL-escapes).
function substitute_canary(template, encoded_value)
  local out, n = string.gsub(template, "CANARY", encoded_value, 1)
  return out
end

---
-- Reject NUL/CR/LF/whitespace and non-relative paths so the HTTP request line
-- cannot be split or turned into an absolute-form request-target.
-- @return Error message string, or <code>nil</code> if OK.
function assert_safe_http_request_path(path)
  if type(path) ~= "string" then
    return "path must be a string"
  end
  if #path > MAX_HTTP_PATH then
    return "path exceeds maximum length"
  end
  if path == "" then
    return "path must not be empty"
  end
  if string.sub(path, 1, 1) ~= "/" then
    return "path must start with /"
  end
  if string.find(path, "[\0\r\n]") then
    return "path must not contain NUL, CR, or LF"
  end
  if string.find(path, "%s") then
    return "path must not contain whitespace"
  end
  return nil
end

---
-- Script-args basepath prefix (may be empty). If set, must start with <code>/</code>.
-- @return Error message string, or <code>nil</code> if OK.
function assert_safe_basepath(prefix)
  if prefix == nil or prefix == "" then
    return nil
  end
  if type(prefix) ~= "string" then
    return "basepath must be a string"
  end
  if #prefix > MAX_HTTP_PATH then
    return "basepath exceeds maximum length"
  end
  if string.sub(prefix, 1, 1) ~= "/" then
    return "basepath must be empty or start with /"
  end
  if string.find(prefix, "[\0\r\n]") then
    return "basepath must not contain NUL, CR, or LF"
  end
  if string.find(prefix, "%s") then
    return "basepath must not contain whitespace"
  end
  return nil
end

return _ENV
