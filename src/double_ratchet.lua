-- double_ratchet.lua - Signal Protocol Double Ratchet State Machine (real crypto)
--
-- Implements the Double Ratchet algorithm (Perrin & Marlinspike spec):
--   - Symmetric ratchet: message keys derived from chain keys via HMAC-SHA256
--   - DH ratchet: new X25519 key pair per ratchet step, root key advanced via HKDF
--   - Skipped-message keys stored for out-of-order delivery (bounded by MAX_SKIP)
--
-- Bootstrap:
--   Initiator: new(shared_secret, true,  remote_spk_pub_hex, nil)
--   Receiver:  new(shared_secret, false, nil, my_spk_priv_hex)
--
-- Message format (JSON-friendly):
--   { header = { dh = hex, n = number, pn = number }, nonce = hex, ct = hex, tag = hex }
--
-- Associated data (ad) must be identical on both sides; the client passes
--   ad = sender_identity_pub_hex .. receiver_identity_pub_hex

local crypto = require("src.crypto")

local MAX_SKIP = 100
local INFO_RATCHET = "E2EEChat-Ratchet"

local DoubleRatchet = {}
DoubleRatchet.__index = DoubleRatchet

-- KDF_RK(rk, dh_out) -> (rk', ck)   [HKDF-SHA256, 64 bytes split in half]
local function kdf_rk(rk, dh_out)
    local okm = crypto.hkdf(rk, dh_out, INFO_RATCHET, 64)
    return okm:sub(1, 32), okm:sub(33, 64)
end

-- KDF_CK(ck) -> (mk, ck')           [HMAC-SHA256 with constant inputs 0x01 / 0x02]
local function kdf_ck(ck)
    return crypto.hmac_sha256(ck, "\x01"), crypto.hmac_sha256(ck, "\x02")
end

function DoubleRatchet.new(shared_secret, is_initiator, remote_dh_pub, local_dh_priv)
    local self = setmetatable({}, DoubleRatchet)
    self.RK = shared_secret
    self.CKs = nil
    self.CKr = nil
    self.DHs = nil
    self.DHr = nil
    self.Ns = 0
    self.Nr = 0
    self.PN = 0
    self.skipped = {} -- "dh_pub_hex:n" -> message key (raw 32 bytes)
    self.seen_dhs = {} -- remote DH pubs already ratcheted to (replay guard)

    if is_initiator then
        assert(remote_dh_pub, "initiator bootstrap requires the remote DH public key")
        self.DHs = crypto.gen_x25519()
        self.DHr = remote_dh_pub
        self.seen_dhs[remote_dh_pub] = true
        self.RK, self.CKs = kdf_rk(self.RK, crypto.x25519(self.DHs.private, self.DHr))
    else
        assert(local_dh_priv, "receiver bootstrap requires the local DH private key (SPK)")
        self.DHs = { private = local_dh_priv, public = crypto.pub_from_priv(local_dh_priv) }
        -- DHr, CKs, CKr established on first received message
    end
    return self
end

-- DH ratchet step (spec order matters):
--   1. derive new receiving chain from the CURRENT local DH against the new remote DH
--   2. generate a NEW local DH pair
--   3. derive new sending chain from the new local DH against the new remote DH
function DoubleRatchet:ratchet_step(remote_dh_pub)
    self.PN = self.Ns
    self.Ns = 0
    self.Nr = 0
    self.DHr = remote_dh_pub
    self.seen_dhs[remote_dh_pub] = true
    self.RK, self.CKr = kdf_rk(self.RK, crypto.x25519(self.DHs.private, self.DHr))
    self.DHs = crypto.gen_x25519()
    self.RK, self.CKs = kdf_rk(self.RK, crypto.x25519(self.DHs.private, self.DHr))
end

-- Stash message keys for skipped messages in the current receive chain
function DoubleRatchet:skip_messages(until_index)
    if not self.CKr or not self.DHr then return end
    if until_index - self.Nr > MAX_SKIP then
        error("too many skipped messages (" .. (until_index - self.Nr) .. ")")
    end
    while self.Nr < until_index do
        local mk, next_ck = kdf_ck(self.CKr)
        self.skipped[self.DHr .. ":" .. self.Nr] = mk
        self.CKr = next_ck
        self.Nr = self.Nr + 1
    end
end

function DoubleRatchet:encrypt(plaintext, ad)
    assert(self.CKs, "no sending chain established")
    local mk, next_ck = kdf_ck(self.CKs)
    self.CKs = next_ck
    local header = { dh = self.DHs.public, n = self.Ns, pn = self.PN }
    self.Ns = self.Ns + 1
    local aad = ad .. header.dh .. header.n .. header.pn
    local enc = crypto.aes_gcm_encrypt(mk, plaintext, aad)
    enc.header = header
    return enc
end

function DoubleRatchet:decrypt(msg, ad)
    local header = msg.header
    if type(header) ~= "table" or type(header.dh) ~= "string"
        or type(header.n) ~= "number" or type(header.pn) ~= "number" then
        error("malformed ratchet header")
    end
    local aad = ad .. header.dh .. header.n .. header.pn

    -- 1. Previously skipped message?
    local skipped_key = header.dh .. ":" .. header.n
    local stored_mk = self.skipped[skipped_key]
    if stored_mk then
        self.skipped[skipped_key] = nil -- consume (one-shot)
        local pt = crypto.aes_gcm_decrypt(stored_mk, msg.nonce, msg.ct, msg.tag, aad)
        if pt == nil then
            -- Keep the key so a legitimate copy of this index can still decrypt
            self.skipped[skipped_key] = stored_mk
        end
        return pt
    end

    -- 2. New DH ratchet step?
    if header.dh ~= self.DHr then
        if self.seen_dhs[header.dh] then
            -- Already ratcheted past this DH and no skipped key stored:
            -- a stale/replayed message. Reject without corrupting ratchet state.
            error("stale ratchet message (possible replay)")
        end
        self:skip_messages(header.pn) -- keys for late messages of the old chain
        self:ratchet_step(header.dh)
    end

    -- 3. Advance the receive chain to the message index
    if not self.CKr then
        error("no receiving chain established")
    end
    if header.n < self.Nr then
        -- Index already consumed: replay of a message whose key is gone.
        error("message index already consumed (possible replay)")
    end
    if header.n - self.Nr > MAX_SKIP then
        error("too many skipped messages (" .. (header.n - self.Nr) .. ")")
    end
    while self.Nr < header.n do
        local mk, next_ck = kdf_ck(self.CKr)
        self.skipped[self.DHr .. ":" .. self.Nr] = mk
        self.CKr = next_ck
        self.Nr = self.Nr + 1
    end
    local used_n = self.Nr
    local mk, next_ck = kdf_ck(self.CKr)
    self.CKr = next_ck
    self.Nr = used_n + 1
    local pt = crypto.aes_gcm_decrypt(mk, msg.nonce, msg.ct, msg.tag, aad)
    if pt == nil then
        -- Decryption failed (tampered/garbage): keep the consumed key so a
        -- legitimate retry of this index can still decrypt. Chain stays aligned.
        self.skipped[self.DHr .. ":" .. used_n] = mk
    end
    return pt
end

return DoubleRatchet
