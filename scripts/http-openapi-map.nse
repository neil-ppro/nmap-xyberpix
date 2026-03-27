local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Probes common OpenAPI/Swagger documentation paths, parses JSON when possible,
and highlights paths whose names suggest sensitive operations (admin, upload,
delete, internal, debug, exec, token, password).

Use only on systems you are authorized to test.
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local SENSITIVE = {
  "admin", "delete", "upload", "internal", "debug", "exec", "token",
  "password", "secret", "graphql", "swagger", "actuator", "jolokia",
}

local PATHS = {
  "/openapi.json",
  "/v3/api-docs",
  "/v2/api-docs",
  "/swagger.json",
  "/api/swagger.json",
  "/api-docs/swagger.json",
  "/swagger/v1/swagger.json",
  "/api/openapi.json",
}

local function path_flags(path)
  local low = string.lower(path or "")
  local hits = {}
  for _, w in ipairs(SENSITIVE) do
    if string.find(low, w, 1, true) then
      hits[#hits + 1] = w
    end
  end
  return hits
end

local function extract_paths_from_openapi(doc)
  local out = {}
  if type(doc) ~= "table" or type(doc.paths) ~= "table" then
    return out
  end
  for p, _ in pairs(doc.paths) do
    if type(p) == "string" then
      out[#out + 1] = p
    end
  end
  table.sort(out)
  return out
end

action = function(host, port)
  local base = stdnse.get_script_args(SCRIPT_NAME .. ".basepath") or ""
  local found = {}
  local interesting = {}

  for _, p in ipairs(PATHS) do
    local path = base .. p
    local resp = http.get(host, port, path)
    if resp and resp.status == 200 and resp.body and #resp.body > 20 then
      local ct = (resp.header and resp.header["content-type"]) or ""
      if string.find(string.lower(ct), "json", 1, true) or string.match(resp.body, "^%s*{") then
        local ok, doc = pcall(json.parse, resp.body)
        local paths = {}
        if ok and type(doc) == "table" then
          paths = extract_paths_from_openapi(doc)
        end
        if #paths == 0 and string.find(resp.body, '"paths"%s*:') then
          for m in string.gmatch(resp.body, '"(/[^"]+)"%s*:') do
            if string.sub(m, 1, 1) == "/" then
              paths[#paths + 1] = m
            end
          end
        end
        found[#found + 1] = {url = path, path_count = #paths, sample = {}}
        local lim = 0
        for _, pp in ipairs(paths) do
          local flags = path_flags(pp)
          if #flags > 0 then
            interesting[#interesting + 1] = pp .. " (" .. table.concat(flags, ",") .. ")"
          end
          lim = lim + 1
          if lim <= 8 then
            found[#found].sample[#found[#found].sample + 1] = pp
          end
        end
      end
    end
  end

  if #found == 0 then
    return stdnse.format_output(false, "No common OpenAPI/Swagger JSON endpoints found.")
  end

  local lines = {}
  for _, f in ipairs(found) do
    lines[#lines + 1] = ("%s: ~%d paths"):format(f.url, f.path_count)
    if #f.sample > 0 then
      lines[#lines + 1] = "  sample: " .. table.concat(f.sample, ", ")
    end
  end
  if #interesting > 0 then
    lines[#lines + 1] = "Flagged path names:"
    for _, x in ipairs(interesting) do
      lines[#lines + 1] = "  " .. x
    end
  end
  return stdnse.format_output(true, lines)
end
