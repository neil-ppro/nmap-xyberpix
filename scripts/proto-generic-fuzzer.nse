local http_offsec = require "http_offsec"
local nmap = require "nmap"
local proto_fuzz = require "proto_fuzz"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Sends mutated binary payloads to an open TCP, UDP, or SSL/TLS port for
authorized protocol fuzzing and robustness testing. Each iteration may use a
different mutation strategy (bit flips, inserts, truncation, random blocks,
etc.).

**Requires explicit opt-in:** set ``proto-generic-fuzzer.unsafe=1`` after you
have **written authorization** for the target. This script can crash services,
trigger firewalls, or contribute to denial of service.

Provide a seed payload as hex (``payload_hex``) and/or generate a random blob
(``random_len``). Cap: ``iterations`` ≤ 500, payload size bounded by the
library (see ``nselib/proto_fuzz.lua``).

Strategies (comma-separated ``strategies=``): ``noop``, ``bitflip``,
``byte_inc``, ``byte_dec``, ``byte_random``, ``insert_byte``, ``delete_byte``,
``truncate``, ``append_random``, ``prepend_random``, ``swap_adjacent``,
``duplicate_chunk``, ``reverse_block``, ``null_inject``,
``replace_slice_random``. Default: all except ``noop``.

Example (authorized lab only):

```
nmap -p 9999 --script proto-generic-fuzzer \
  --script-args 'proto-generic-fuzzer.unsafe=1,proto-generic-fuzzer.payload_hex=47455420,proto-generic-fuzzer.iterations=20,proto-generic-fuzzer.strategies=bitflip,truncate'
```
]]

author = "nmap-ppro"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "fuzzer"}

---
-- @usage
-- nmap -p 9000 --script proto-generic-fuzzer --script-args 'proto-generic-fuzzer.unsafe=1,proto-generic-fuzzer.random_len=32,proto-generic-fuzzer.iterations=5'
--
-- @args proto-generic-fuzzer.unsafe Must be ``1`` or ``true`` to run.
-- @args proto-generic-fuzzer.payload_hex Even-length hex string (whitespace allowed).
-- @args proto-generic-fuzzer.random_len Generate this many random bytes when no hex payload.
-- @args proto-generic-fuzzer.strategies Comma-separated strategy names (see description).
-- @args proto-generic-fuzzer.iterations Number of send iterations (default 10, max 500).
-- @args proto-generic-fuzzer.chain_depth Mutations chained per iteration (default 1, max 8).
-- @args proto-generic-fuzzer.transport ``tcp`` (default), ``udp``, or ``ssl``.
-- @args proto-generic-fuzzer.reuse If ``1``, keep one connection for all iterations (TCP/SSL).
-- @args proto-generic-fuzzer.delay_ms Milliseconds to sleep between iterations (default 0).
-- @args proto-generic-fuzzer.recv If ``0``, do not read after send (default read up to recv_bytes).
-- @args proto-generic-fuzzer.recv_bytes Max bytes to read per iteration (default 4096).
-- @args proto-generic-fuzzer.seed Optional numeric seed for ``math.random``.

portrule = function(host, port)
  local p = port.number
  if p == nil then
    return false
  end
  return port.state == "open" or port.state == "open|filtered"
end

local function split_csv(s)
  local out = {}
  if type(s) ~= "string" or s == "" then
    return out
  end
  for part in string.gmatch(s, "([^,]+)") do
    local t = (part:match("^%s*(.-)%s*$"))
    if t ~= "" then
      out[#out + 1] = t
    end
  end
  return out
end

local function parse_transport(port)
  local t = stdnse.get_script_args(SCRIPT_NAME .. ".transport")
  t = type(t) == "string" and t:lower() or nil
  if t == "udp" then
    return "udp", "udp"
  elseif t == "ssl" or t == "tls" then
    return "ssl", "tcp"
  end
  if port.protocol == "udp" then
    return "udp", "udp"
  end
  return "tcp", "tcp"
end

action = function(host, port)
  local gate = http_offsec.intrusive_gate(SCRIPT_NAME)
  if gate then
    return stdnse.format_output(false, gate)
  end

  local hex = stdnse.get_script_args(SCRIPT_NAME .. ".payload_hex")
  local rlen = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".random_len"))
  local base, err

  if type(hex) == "string" and hex ~= "" then
    base, err = proto_fuzz.decode_hex(hex)
    if not base then
      return stdnse.format_output(false, "payload_hex: " .. tostring(err))
    end
  end

  if not base and rlen then
    base, err = proto_fuzz.random_payload(rlen)
    if not base then
      return stdnse.format_output(false, "random_len: " .. tostring(err))
    end
  end

  if not base then
    return stdnse.format_output(
      false,
      "Set proto-generic-fuzzer.payload_hex=HEX and/or proto-generic-fuzzer.random_len=N."
    )
  end

  local seed = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".seed"))
  if seed then
    math.randomseed(math.floor(seed))
  end

  local iterations = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".iterations")) or 10
  if iterations < 1 then
    iterations = 1
  end
  if iterations > 500 then
    iterations = 500
  end

  local chain_depth = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".chain_depth")) or 1
  if chain_depth < 1 then
    chain_depth = 1
  end
  if chain_depth > 8 then
    chain_depth = 8
  end

  local strat_arg = stdnse.get_script_args(SCRIPT_NAME .. ".strategies")
  local pool = split_csv(strat_arg)
  if #pool == 0 then
    pool = proto_fuzz.strategy_names()
    local filtered = {}
    for _, n in ipairs(pool) do
      if n ~= "noop" then
        filtered[#filtered + 1] = n
      end
    end
    pool = filtered
  end
  if #pool == 0 then
    return stdnse.format_output(false, "No strategies in pool.")
  end

  local delay_ms = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".delay_ms")) or 0
  if delay_ms < 0 then
    delay_ms = 0
  end

  local recv_on = stdnse.get_script_args(SCRIPT_NAME .. ".recv")
  local do_recv = not (recv_on == "0" or recv_on == "false")

  local recv_bytes = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".recv_bytes")) or 4096
  if recv_bytes < 0 then
    recv_bytes = 0
  end
  if recv_bytes > proto_fuzz.MAX_PAYLOAD_BYTES then
    recv_bytes = proto_fuzz.MAX_PAYLOAD_BYTES
  end

  local reuse = stdnse.get_script_args(SCRIPT_NAME .. ".reuse")
  local reuse_conn = reuse == "1" or reuse == "true"

  local sock_proto, nmap_proto = parse_transport(port)
  local connect_proto = sock_proto == "ssl" and "ssl" or nil

  local results = {}
  local sock

  local function ensure_socket()
    if sock then
      return true
    end
    sock = nmap.new_socket(nmap_proto)
    sock:set_timeout(stdnse.get_timeout(host))
    local ok, cerr = sock:connect(host, port, connect_proto)
    if not ok then
      results[#results + 1] = "connect failed: " .. tostring(cerr)
      return false
    end
    return true
  end

  local function close_socket()
    if sock then
      pcall(function()
        sock:close()
      end)
      sock = nil
    end
  end

  for it = 1, iterations do
    if not reuse_conn or it == 1 then
      close_socket()
      if not ensure_socket() then
        break
      end
    end

    local payload
    if chain_depth <= 1 then
      local pick = pool[math.random(1, #pool)]
      payload = proto_fuzz.mutate_once(base, pick)
      results[#results + 1] = ("iter=%d strategy=%s sent=%d"):format(
        it, pick, #payload)
    else
      payload = proto_fuzz.mutate_chain(base, pool, chain_depth)
      results[#results + 1] = ("iter=%d chain_depth=%d sent=%d"):format(
        it, chain_depth, #payload)
    end

    local ok, serr = sock:send(payload)
    if not ok then
      results[#results + 1] = "  send error: " .. tostring(serr)
      close_socket()
      if reuse_conn then
        break
      end
    else
      if do_recv and recv_bytes > 0 then
        local rok, data = sock:receive_bytes(recv_bytes)
        if rok and data then
          results[#results + 1] = ("  recv_bytes=%d preview=%s"):format(
            #data,
            stdnse.tohex(data:sub(1, math.min(32, #data))) .. (#data > 32 and "..." or ""))
        else
          results[#results + 1] = "  recv: " .. tostring(data)
        end
      end
    end

    if not reuse_conn then
      close_socket()
    end

    if delay_ms > 0 then
      stdnse.sleep(delay_ms / 1000)
    end
  end

  close_socket()
  results[#results + 1] = "Authorized use only; review server-side logs and crashes manually."
  return stdnse.format_output(true, results)
end
