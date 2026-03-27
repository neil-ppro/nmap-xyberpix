local http = require "http"
local http_offsec = require "http_offsec"
local rand = require "rand"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Sends WebSocket upgrade probes to common paths. Reports HTTP 101 Switching
Protocols or presence of Sec-WebSocket-Accept. Useful to find WS endpoints
that may lack origin checks (follow-up testing required).

Authorized testing only.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local PATHS = {"/", "/ws", "/websocket", "/socket", "/realtime", "/live", "/graphql"}

action = function(host, port)
  local base = stdnse.get_script_args(SCRIPT_NAME .. ".basepath") or ""
  local err = http_offsec.assert_safe_basepath(base)
  if err then
    return stdnse.format_output(false, err)
  end
  local key = rand.random_string(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
  local lines = {}

  for _, p in ipairs(PATHS) do
    local path = base .. p
    err = http_offsec.assert_safe_http_request_path(path)
    if err then
      return stdnse.format_output(false, err)
    end
    local opts = {
      header = {
        ["Upgrade"] = "websocket",
        ["Connection"] = "Upgrade",
        ["Sec-WebSocket-Key"] = key,
        ["Sec-WebSocket-Version"] = "13",
      },
    }
    local resp = http.generic_request(host, port, "GET", path, opts)
    if resp and resp.status then
      local st = tostring(resp.status)
      local ws_accept = resp.header and (resp.header["Sec-WebSocket-Accept"] or resp.header["sec-websocket-accept"])
      if st == "101" or ws_accept then
        lines[#lines + 1] = ("%s -> %s%s"):format(
          path,
          st,
          ws_accept and (" Accept=" .. tostring(ws_accept)) or ""
        )
      elseif resp.header and string.lower(tostring(resp.header["Upgrade"] or "")):find("websocket", 1, true) then
        lines[#lines + 1] = path .. " -> " .. st .. " (Upgrade: websocket header without 101)"
      end
    end
  end

  if #lines == 0 then
    return stdnse.format_output(false, "No obvious WebSocket handshake responses on probed paths.")
  end
  return stdnse.format_output(true, lines)
end
