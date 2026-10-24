-- test.lua - Automated test suite for Signal Protocol & Lua E2EE Chat
--
-- Validates real cryptographic behaviour:
--   * RFC 4231 (HMAC-SHA256) and RFC 5869 (HKDF) known-answer vectors
--   * X25519 key agreement, Ed25519 signatures, AES-256-GCM auth
--   * X3DH initiator/receiver shared-secret agreement
--   * Double Ratchet: both directions, out-of-order, replay, tamper rejection

local crypto = require("src.crypto")
local double_ratchet = require("src.double_ratchet")

local passed, failed = 0, 0

local function check(name, cond, detail)
    if cond then
        passed = passed + 1
        print("  [PASS] " .. name)
    else
        failed = failed + 1
        print("  [FAIL] " .. name .. (detail and (" - " .. tostring(detail)) or ""))
    end
end

print("Running Signal Protocol Test Suite...")

-- 1. X25519 keygen + symmetric key agreement
local a = crypto.gen_x25519()
local b = crypto.gen_x25519()
local s1 = crypto.x25519(a.private, b.public)
local s2 = crypto.x25519(b.private, a.public)
check("X25519 keygen", #a.public == 64 and #a.private == 64)
check("X25519 symmetric derive", s1 == s2 and #s1 == 32)

-- 2. Ed25519 sign/verify + tamper rejection
local ed = crypto.gen_ed25519()
local sig = crypto.ed25519_sign(ed.private, "hello world")
check("Ed25519 sign", #sig == 128)
check("Ed25519 verify ok", crypto.ed25519_verify(ed.public, "hello world", sig) == true)
check("Ed25519 verify tampered msg", crypto.ed25519_verify(ed.public, "hello worlt", sig) == false)
check("Ed25519 verify tampered sig", crypto.ed25519_verify(ed.public, "hello world", sig:sub(1, 126) .. "zz") == false)

-- 3. HMAC-SHA256 - RFC 4231 Test Case 1
local h = crypto.hmac_sha256(string.rep("\x0b", 20), "Hi There")
check("HMAC-SHA256 RFC4231 TC1", crypto.to_hex(h) ==
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", crypto.to_hex(h))

-- 4. HKDF-SHA256 - RFC 5869 Test Case 1
local okm = crypto.hkdf(
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
    string.rep("\x0b", 22),
    "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
    42)
check("HKDF-SHA256 RFC5869 TC1", crypto.to_hex(okm) ==
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", crypto.to_hex(okm))

-- 5. AES-256-GCM roundtrip + tamper rejection
local key = crypto.random_bytes(32)
local enc = crypto.aes_gcm_encrypt(key, "secret message", "aad-data")
check("AES-GCM encrypt", enc.ct and enc.nonce and enc.tag and #enc.tag == 32)
local pt = crypto.aes_gcm_decrypt(key, enc.nonce, enc.ct, enc.tag, "aad-data")
check("AES-GCM decrypt roundtrip", pt == "secret message", tostring(pt))
local bad = crypto.aes_gcm_decrypt(key, enc.nonce, enc.ct:sub(1, -4) .. "000", enc.tag, "aad-data")
check("AES-GCM tampered ct rejected", bad == nil)
local bad2 = crypto.aes_gcm_decrypt(key, enc.nonce, enc.ct, enc.tag, "wrong-aad")
check("AES-GCM wrong aad rejected", bad2 == nil)
local empty = crypto.aes_gcm_encrypt(key, "", "aad")
check("AES-GCM empty plaintext", crypto.aes_gcm_decrypt(key, empty.nonce, empty.ct, empty.tag, "aad") == "")

-- 6. X3DH initiator/receiver agreement (with and without OPK)
local bob_cm, alice_cm = crypto.new(), crypto.new()
local bundle = bob_cm:get_upload_bundle()
local opk = bundle.opks[1]
local bundle_with = { ik = bundle.ik, spk = bundle.spk, spk_sig = bundle.spk_sig,
    ed_id = bundle.ed_id, opk = { id = opk.id, pub = opk.pub } }
local sk_a, ek_pub = alice_cm:x3dh_initiator(bundle_with)
local sk_b = bob_cm:x3dh_receiver(bob_cm.identity_key.private, bob_cm.signed_prekey.private,
    bob_cm:get_opk_priv(opk.id), alice_cm.identity_key.public, ek_pub)
check("X3DH agreement (with OPK)", sk_a == sk_b and #sk_a == 32)

local bundle_without = { ik = bundle.ik, spk = bundle.spk, spk_sig = bundle.spk_sig, ed_id = bundle.ed_id }
local sk_a2, ek2 = alice_cm:x3dh_initiator(bundle_without)
local sk_b2 = bob_cm:x3dh_receiver(bob_cm.identity_key.private, bob_cm.signed_prekey.private,
    nil, alice_cm.identity_key.public, ek2)
check("X3DH agreement (no OPK)", sk_a2 == sk_b2 and #sk_a2 == 32)

-- 7. X3DH rejects a tampered SPK signature (MITM guard)
local bad_bundle = { ik = bundle.ik, spk = bundle.spk, spk_sig = string.rep("ab", 32), ed_id = bundle.ed_id }
local ok3, err3 = pcall(function() return alice_cm:x3dh_initiator(bad_bundle) end)
check("X3DH rejects bad SPK signature", not ok3, tostring(err3))

-- 8. Double Ratchet: full conversation, both directions
local ad_ab = alice_cm.identity_key.public .. bob_cm.identity_key.public
local ad_ba = bob_cm.identity_key.public .. alice_cm.identity_key.public
local ra = double_ratchet.new(sk_a, true, bundle_with.spk, nil)
local rb = double_ratchet.new(sk_b, false, nil, bob_cm.signed_prekey.private)

local m1 = ra:encrypt("hello bob", ad_ab)
check("Ratchet A->B (first msg)", rb:decrypt(m1, ad_ab) == "hello bob")
local m2 = rb:encrypt("hi alice", ad_ba)
check("Ratchet B->A (first msg)", ra:decrypt(m2, ad_ba) == "hi alice")

local rounds_ok = true
for i = 1, 5 do
    local ma = ra:encrypt("ping " .. i, ad_ab)
    local mb = rb:encrypt("pong " .. i, ad_ba)
    if rb:decrypt(ma, ad_ab) ~= "ping " .. i then rounds_ok = false end
    if ra:decrypt(mb, ad_ba) ~= "pong " .. i then rounds_ok = false end
end
check("Ratchet 5 bidirectional rounds", rounds_ok)

-- 9. Out-of-order delivery (skipped message keys)
local o1 = ra:encrypt("o1", ad_ab)
local o2 = ra:encrypt("o2", ad_ab)
local o3 = ra:encrypt("o3", ad_ab)
check("Out-of-order 3rd first", rb:decrypt(o3, ad_ab) == "o3")
check("Out-of-order 1st later", rb:decrypt(o1, ad_ab) == "o1")
check("Out-of-order 2nd later", rb:decrypt(o2, ad_ab) == "o2")

-- 10. Replay protection: skipped-key message decrypts once, then is rejected
local rep1_ok, rep1 = pcall(rb.decrypt, rb, o1, ad_ab)
local rep2_ok, rep2 = pcall(rb.decrypt, rb, o1, ad_ab)
check("Replay rejected on second attempt", rep2 == nil or not rep2_ok,
    "first=" .. tostring(rep1) .. " second=" .. tostring(rep2))

-- 11. Tamper rejection (GCM authentication)
local t = ra:encrypt("tamper me", ad_ab)
t.ct = t.ct:sub(1, -4) .. "000"
local t_ok, t_res = pcall(rb.decrypt, rb, t, ad_ab)
check("Tampered ciphertext rejected", (not t_ok) or t_res == nil)

-- 12. Long conversation after tampering (session must stay aligned)
local bulk_ok = true
for i = 1, 30 do
    local msg = ra:encrypt("bulk " .. i, ad_ab)
    if rb:decrypt(msg, ad_ab) ~= "bulk " .. i then bulk_ok = false end
end
check("30-message bulk after tamper attempt", bulk_ok)

-- 13. Client module integration (no network): bundle shape + session objects
local client_mod = require("src.client")
local alice_client = client_mod.new("Alice", "127.0.0.1", 8888)
local upload = alice_client.crypto:get_upload_bundle()
check("Client prekey bundle shape", upload.ik and upload.spk and upload.spk_sig
    and upload.ed_id and #upload.opks == 5)
check("Client SPK signature valid",
    crypto.ed25519_verify(upload.ed_id, crypto.from_hex(upload.spk), upload.spk_sig))

-- 14. Fingerprint (human-comparable IK hash, Signal-style 60 digits)
local fp_kat = crypto.fingerprint(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
check("Fingerprint known-answer (SHA-256 KAT)", fp_kat ==
    "99130 54102 96510 24518 84728 77891 79441 86456 15457 80071 93848 82715",
    "got: " .. tostring(fp_kat))

local fp_a = crypto.fingerprint(alice_client.crypto.identity_key.public)
local fp_b = crypto.fingerprint(client_mod.new("Bob", "127.0.0.1", 8888).crypto.identity_key.public)
local fp_shape = #fp_a == 71
    and fp_a:match("^%d%d%d%d%d") ~= nil
    and fp_a:match("%d%d%d%d%d$") ~= nil
    and select(2, fp_a:gsub(" ", "")) == 11
check("Fingerprint format (12 groups of 5 digits)", fp_shape, "got: " .. fp_a)
check("Fingerprints differ across keys", fp_a ~= fp_b)
check("Fingerprint deterministic", crypto.fingerprint(alice_client.crypto.identity_key.public) == fp_a)

-- 15. Plugin display filter + colorize plugin
local plugin_manager = require("src.plugin")
local colorize = require("plugins.colorize")

check("Filter passes value through with no listeners",
    plugin_manager:filter("display_test_none", "hi") == "hi")

plugin_manager:on("filter_test", function(v) return v .. "-1" end)
plugin_manager:on("filter_test", function(v) return v .. "-2" end)
check("Filter chains transforms", plugin_manager:filter("filter_test", "x") == "x-1-2")

plugin_manager:on("filter_test", function() return nil end)   -- ignored
plugin_manager:on("filter_test", function() error("boom") end) -- pcall-caught
check("Filter tolerates nil/error returns", plugin_manager:filter("filter_test", "y") == "y-1-2")

check("Colorize disabled leaves text unchanged",
    colorize.colorize("[Error] boom", false) == "[Error] boom")
check("Colorize plain text unchanged when enabled",
    colorize.colorize("hello", true) == "hello")
check("Colorize error line is red",
    colorize.colorize("[Error] boom", true) == "\27[31m[Error] boom\27[0m")
check("Colorize system notice is yellow",
    colorize.colorize("* @bob has joined the chat.", true) ==
    "\27[33m* @bob has joined the chat.\27[0m")
check("Colorize online roster is cyan",
    colorize.colorize("online: @alice @bob", true) ==
    "\27[36monline: @alice @bob\27[0m")
check("Colorize sent tick is dim gray",
    colorize.colorize("✓", true) == "\27[90m✓\27[0m")
check("Colorize delivered tick is green",
    colorize.colorize("✓✓", true) == "\27[32m✓✓\27[0m")
local dm_a = colorize.colorize("alice: hi", true)
local dm_b = colorize.colorize("bob: hi", true)
check("Colorize DM uses 256-color wrap",
    dm_a:match("^\27%[38;5;%d+malice: hi\27%[0m$") ~= nil, dm_a)
check("Colorize DM color deterministic", dm_a == colorize.colorize("alice: hi", true))
check("Colorize distinct senders get distinct colors", dm_a ~= dm_b,
    "alice=" .. dm_a .. " bob=" .. dm_b)

-- 16. Plugin load_dir scope filtering
local function count_named(mgr, name)
    local n = 0
    for _, p in ipairs(mgr.plugins) do
        if p.name == name then n = n + 1 end
    end
    return n
end

plugin_manager:load_dir("plugins", "server")
check("load_dir registers server-scoped plugin", count_named(plugin_manager, "EventLogger") == 1)
check("load_dir skips other-scope plugins", count_named(plugin_manager, "Colorize") == 0)

plugin_manager:load_dir("plugins", "client")
check("load_dir registers client-scoped plugin", count_named(plugin_manager, "Colorize") == 1)

-- display_tick filter (used when the client rewrites the input line in place)
local tick_sent_f = plugin_manager:filter("display_tick", "✓")
local tick_deliv_f = plugin_manager:filter("display_tick", "✓✓")
if colorize.enabled then
    check("display_tick sent is dim gray", tick_sent_f == "\27[90m✓\27[0m", tick_sent_f)
    check("display_tick delivered is green", tick_deliv_f == "\27[32m✓✓\27[0m", tick_deliv_f)
else
    check("display_tick passthrough when colors disabled",
        tick_sent_f == "✓" and tick_deliv_f == "✓✓")
end

local tmp_path = "plugins/zzz_unscoped_test_plugin.lua"
local f = io.open(tmp_path, "w")
if f then
    f:write("return { name = 'UnscopedTest' }\n")
    f:close()
    plugin_manager:load_dir("plugins", "server")
    check("load_dir skips unscoped plugins", count_named(plugin_manager, "UnscopedTest") == 0)
    os.remove(tmp_path)
end

plugin_manager:load_dir("plugins_nonexistent_dir", "server")
check("load_dir tolerates missing directory", true)

-- 17. Delivery-tick bookkeeping (pure ack_transition, no printing)
local pending = {}
local group = { left = 3 }
pending.n1, pending.n2, pending.n3 = group, group, group
local at = client_mod.ack_transition
check("ack waiting while receipts remain", at(pending, "n1") == "waiting" and group.left == 2)
check("ack waiting again", at(pending, "n2") == "waiting" and group.left == 1)
check("ack done on final receipt", at(pending, "n3") == "done")
check("group cleared after done", pending.n1 == nil and pending.n2 == nil and pending.n3 == nil)
check("duplicate receipt ignored", at(pending, "n3") == nil)
check("unknown nonce ignored", at(pending, "nope") == nil)

-- Single-recipient DM: first receipt completes immediately
local dm_pending = {}
dm_pending.abc = { left = 1 }
check("single-recipient ack done at once", at(dm_pending, "abc") == "done" and dm_pending.abc == nil)

print(string.format("\n%d passed, %d failed", passed, failed))
if failed > 0 then os.exit(1) end
print("All Signal Protocol tests passed successfully!")
