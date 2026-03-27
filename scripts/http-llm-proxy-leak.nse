local http = require "http"
local http_offsec = require "http_offsec"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Probes common LLM HTTP API paths (OpenAI-style and generic) with GET/OPTIONS
and a dummy Authorization header. Flags responses when error bodies mention
common leak patterns (e.g. sk-, traceback) or small JSON error payloads.

Requires http-llm-proxy-leak.unsafe=1 (noisy / may log on target).

Authorized testing only.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.http

local PATHS = {
  "/v1/models",
  "/v1/chat/completions",
  "/v1/embeddings",
  "/api/v1/generate",
  "/v1/messages",
}

local LEAK_HINTS = {
  "sk-",
  "api_key",
  "apikey",
  "openai",
  "anthropic",
  "traceback",
  "exception",
  "secret",
}

action = function(host, port)
  local gate = http_offsec.intrusive_gate(SCRIPT_NAME)
  if gate then
    return stdnse.format_output(false, gate)
  end

  local base = stdnse.get_script_args(SCRIPT_NAME .. ".basepath") or ""
  local perr = http_offsec.assert_safe_basepath(base)
  if perr then
    return stdnse.format_output(false, perr)
  end
  local lines = {}
  local hdr = {["Authorization"] = "Bearer invalid-token-for-nmap-probe"}

  for _, p in ipairs(PATHS) do
    local path = base .. p
    perr = http_offsec.assert_safe_http_request_path(path)
    if perr then
      return stdnse.format_output(false, perr)
    end
    for _, method in ipairs({"GET", "OPTIONS"}) do
      local resp = http.generic_request(host, port, method, path, {header = hdr})
      if resp and resp.body and #resp.body > 0 then
        local low = string.lower(resp.body)
        local found = {}
        for _, h in ipairs(LEAK_HINTS) do
          if string.find(low, h, 1, true) then
            found[#found + 1] = h
          end
        end
        local st = resp.status and tostring(resp.status) or "?"
        local ct = string.lower((resp.header and resp.header["content-type"]) or "")
        local interesting = #found > 0
        if not interesting and st ~= "404" and st ~= "301" and st ~= "302" and #resp.body < 1200 then
          if string.find(ct, "json", 1, true) then
            interesting = true
          end
        end
        if interesting then
          lines[#lines + 1] = ("%s %s -> %s len=%d%s"):format(
            method,
            path,
            st,
            #resp.body,
            #found > 0 and (" hints=" .. table.concat(found, ",")) or ""
          )
        end
      end
    end
  end
  if #lines == 0 then
    return stdnse.format_output(false, "No notable LLM-style API responses on probed paths.")
  end
  return stdnse.format_output(true, lines)
end
