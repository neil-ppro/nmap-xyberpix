---
-- Lightweight mutation helpers for generic TCP/UDP/SSL fuzzing from NSE.
-- Not cryptographically rigorous; intended for authorized protocol testing.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author nmap-ppro

local math = require "math"
local rand = require "rand"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("proto_fuzz", stdnse.seeall)

--- Maximum payload size after mutation (bytes).
MAX_PAYLOAD_BYTES = 65536

--- Maximum expansion per append/prepend step.
MAX_CHUNK = 512

local char = string.char
local sub = string.sub

local function flip_one_bit(b, mask)
  if math.floor(b / mask) % 2 == 0 then
    return b + mask
  else
    return b - mask
  end
end

local function clamp_payload(s)
  if #s <= MAX_PAYLOAD_BYTES then
    return s
  end
  return sub(s, 1, MAX_PAYLOAD_BYTES)
end

--- Strip whitespace and decode hex (same rules as <code>stdnse.fromhex</code>).
-- @return Payload string or <code>nil</code>, error message
function decode_hex(h)
  if type(h) ~= "string" or h == "" then
    return nil, "empty hex"
  end
  local compact = (h:gsub("%s+", ""))
  if #compact % 2 ~= 0 then
    return nil, "hex length must be even"
  end
  local ok, out = pcall(stdnse.fromhex, compact)
  if not ok or type(out) ~= "string" then
    return nil, "invalid hex"
  end
  if #out > MAX_PAYLOAD_BYTES then
    return nil, "decoded payload exceeds MAX_PAYLOAD_BYTES"
  end
  return out
end

--- Random raw payload of <code>len</code> bytes (uses <code>rand.random_string</code>).
function random_payload(len)
  len = tonumber(len) or 0
  if len < 1 or len > MAX_PAYLOAD_BYTES then
    return nil, "random_len out of range"
  end
  return rand.random_string(len)
end

local strategies = {}

strategies.noop = function(s)
  return s
end

strategies.bitflip = function(s)
  if #s < 1 then
    return char(flip_one_bit(0, 2 ^ math.random(0, 7)))
  end
  local i = math.random(1, #s)
  local b = s:byte(i)
  local mask = 2 ^ math.random(0, 7)
  local nb = flip_one_bit(b, mask)
  return sub(s, 1, i - 1) .. char(nb) .. sub(s, i + 1)
end

strategies.byte_inc = function(s)
  if #s < 1 then
    return char(1)
  end
  local i = math.random(1, #s)
  local b = (s:byte(i) + 1) % 256
  return sub(s, 1, i - 1) .. char(b) .. sub(s, i + 1)
end

strategies.byte_dec = function(s)
  if #s < 1 then
    return char(255)
  end
  local i = math.random(1, #s)
  local b = (s:byte(i) - 1) % 256
  return sub(s, 1, i - 1) .. char(b) .. sub(s, i + 1)
end

strategies.byte_random = function(s)
  if #s < 1 then
    return char(math.random(0, 255))
  end
  local i = math.random(1, #s)
  local b = math.random(0, 255)
  return sub(s, 1, i - 1) .. char(b) .. sub(s, i + 1)
end

strategies.insert_byte = function(s)
  local pos = math.random(1, #s + 1)
  local b = char(math.random(0, 255))
  return sub(s, 1, pos - 1) .. b .. sub(s, pos)
end

strategies.delete_byte = function(s)
  if #s < 1 then
    return s
  end
  local i = math.random(1, #s)
  return sub(s, 1, i - 1) .. sub(s, i + 1)
end

strategies.truncate = function(s)
  if #s <= 1 then
    return s
  end
  local n = math.random(1, #s - 1)
  return sub(s, 1, n)
end

strategies.append_random = function(s)
  local n = math.random(1, MAX_CHUNK)
  return clamp_payload(s .. rand.random_string(n))
end

strategies.prepend_random = function(s)
  local n = math.random(1, MAX_CHUNK)
  return clamp_payload(rand.random_string(n) .. s)
end

strategies.swap_adjacent = function(s)
  if #s < 2 then
    return strategies.insert_byte(s)
  end
  local i = math.random(1, #s - 1)
  local a, b = s:byte(i, i + 1)
  return sub(s, 1, i - 1) .. char(b, a) .. sub(s, i + 2)
end

strategies.duplicate_chunk = function(s)
  if #s < 2 then
    return strategies.append_random(s)
  end
  local i = math.random(1, #s - 1)
  local j = math.random(i + 1, #s)
  local chunk = sub(s, i, j)
  local pos = math.random(1, #s + 1)
  return clamp_payload(sub(s, 1, pos - 1) .. chunk .. sub(s, pos))
end

strategies.reverse_block = function(s)
  if #s < 2 then
    return strategies.bitflip(s)
  end
  local i = math.random(1, #s - 1)
  local j = math.random(i, #s)
  local block = sub(s, i, j)
  local rev = {}
  for k = #block, 1, -1 do
    rev[#rev + 1] = sub(block, k, k)
  end
  return sub(s, 1, i - 1) .. table.concat(rev) .. sub(s, j + 1)
end

strategies.null_inject = function(s)
  local pos = math.random(1, #s + 1)
  return sub(s, 1, pos - 1) .. "\0" .. sub(s, pos)
end

strategies.replace_slice_random = function(s)
  if #s < 1 then
    return rand.random_string(math.random(1, 16))
  end
  local i = math.random(1, #s)
  local j = math.random(i, #s)
  local len = j - i + 1
  return sub(s, 1, i - 1) .. rand.random_string(len) .. sub(s, j + 1)
end

--- Ordered list of built-in strategy names (for help text).
function strategy_names()
  local t = {}
  for k in pairs(strategies) do
    t[#t + 1] = k
  end
  table.sort(t)
  return t
end

--- Apply one named strategy; unknown names fall back to <code>bitflip</code>.
function mutate_once(payload, name)
  local fn = strategies[name] or strategies.bitflip
  return clamp_payload(fn(payload))
end

--- Apply <code>depth</code> random strategies from <code>pool</code> (table of names).
function mutate_chain(base, pool, depth)
  local cur = base
  for _ = 1, depth do
    local pick = pool[math.random(1, #pool)]
    cur = mutate_once(cur, pick)
  end
  return cur
end
