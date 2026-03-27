local base64 = require "base64"
local json = require "json"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Parses a JWT from script-args (http-jwt-probe.jwt) and reports header claims
(alg, kid, jku, x5u). Flags alg \"none\" (case variants) and calls out jku/x5u
for manual review. Does not fetch JWKS or perform signature cracking.

Runs once per scan (prerule) when jwt is set. The token may be sensitive.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

prerule = function()
  local j = stdnse.get_script_args(SCRIPT_NAME .. ".jwt")
  return type(j) == "string" and j ~= ""
end

portrule = function()
  return false
end

local function b64url_decode(s)
  if not s or s == "" then
    return nil
  end
  s = string.gsub(s, "-", "+")
  s = string.gsub(s, "_", "/")
  local r = #s % 4
  if r > 0 then
    s = s .. string.rep("=", 4 - r)
  end
  local ok, raw = pcall(base64.dec, s)
  if not ok or not raw then
    return nil
  end
  return raw
end

action = function()
  local token = stdnse.get_script_args(SCRIPT_NAME .. ".jwt")
  local p1 = string.match(token, "^([^.]+)%.")
  if not p1 then
    return stdnse.format_output(false, "JWT must have three dot-separated segments.")
  end
  local hdr_raw = b64url_decode(p1)
  if not hdr_raw then
    return stdnse.format_output(false, "Could not base64url-decode header.")
  end
  hdr_raw = string.gsub(hdr_raw, "%z", "")
  hdr_raw = string.match(hdr_raw, "^%s*(.-)%s*$") or hdr_raw
  local ok, hdr = pcall(json.parse, hdr_raw)
  local lines = {}
  lines[#lines + 1] = "JWT header (decoded JSON):"
  local alg = ""
  if ok and type(hdr) == "table" then
    for k, v in pairs(hdr) do
      lines[#lines + 1] = ("  %s: %s"):format(tostring(k), tostring(v))
    end
    alg = hdr.alg and string.lower(tostring(hdr.alg)) or ""
    if hdr.jku or hdr.x5u then
      lines[#lines + 1] = "NOTE: jku/x5u present - review for URL injection / trust chain issues."
    end
    if hdr.kid and type(hdr.kid) == "string" and string.find(hdr.kid, "../", 1, true) then
      lines[#lines + 1] = "FLAG: kid may contain path traversal characters."
    end
  else
    lines[#lines + 1] = "  (parse fallback) " .. hdr_raw
    alg = string.lower(string.match(hdr_raw, '"alg"%s*:%s*"([^"]*)"') or "")
  end
  if alg == "none" then
    lines[#lines + 1] = "FLAG: alg is \"none\" - verify server rejects unsigned tokens."
  end
  return stdnse.format_output(true, lines)
end
