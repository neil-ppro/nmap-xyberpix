local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Probes common LLM HTTP API paths (OpenAI-style and generic) with GET/OPTIONS
and a dummy Authorization header. Flags verbose error bodies that may leak
model lists, stack traces, or key formats. Does not send real API keys.

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
  local base = stdnse.get_script_args(SCRIPT_NAME .. ".basepath") or ""
  local lines = {}
  local hdr = {["Authorization"] = "Bearer invalid-token-for-nmap-probe"}

  for _, p in ipairs(PATHS) do
    local path = base .. p
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
        if #found > 0 or #resp.body < 800 then
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
