-- GCRA over a theoretical arrival time kept in one key (Story 12.2, FR-65).
--
-- KEYS[1]  rl:<policyId>:<keyHash>
-- ARGV[1]  the emission interval, in microseconds
-- ARGV[2]  the burst tolerance, in microseconds
--
-- The clock is the TIME of the server, so every gateway pod of the fleet decides on one clock.
-- Replies {1, 0} for an admitted request and {0, retry_after_microseconds} for a rejected one.
-- The key expires when the theoretical arrival time is no longer ahead of now, so an idle key is
-- the same as no key.
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000000 + tonumber(time[2])
local interval = tonumber(ARGV[1])
local tolerance = tonumber(ARGV[2])
local stored = tonumber(redis.call('GET', KEYS[1]))
local arrival = now
if stored and stored > now then
  arrival = stored
end
local ahead = arrival - now
if ahead > tolerance then
  return {0, ahead - tolerance}
end
local following = arrival + interval
local remaining_ms = math.ceil((following - now) / 1000) + 1
redis.call('SET', KEYS[1], string.format('%d', following), 'PX', string.format('%d', remaining_ms))
return {1, 0}
