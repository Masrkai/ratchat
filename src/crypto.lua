-- crypto.lua - Real Signal-Protocol cryptographic primitives via OpenSSL (libcrypto) LuaJIT FFI
--
-- Primitives:
--   X25519  keygen / raw export / DH derive      (EVP_PKEY API)
--   Ed25519 keygen / sign / verify               (EVP_DigestSign/Verify, one-shot)
--   HMAC-SHA256 (manual, over EVP_Digest)        (used by HKDF + ratchet chain KDFs)
--   HKDF-SHA256 extract+expand (manual, RFC 5869)
--   AES-256-GCM encrypt/decrypt with auth tags   (EVP_CIPHER API)
--   SHA-256 digest, cryptographically secure randomness (RAND_bytes)
--
-- Key material crosses JSON as lowercase hex; raw bytes are used internally.

local ffi = require("ffi")
local bit = require("bit")

local libcrypto
local load_ok, load_err = pcall(function()
    if ffi.os == "Windows" then
        return ffi.load("libcrypto-3-x64.dll")
    elseif ffi.os == "OSX" then
        return ffi.load("libcrypto.dylib")
    else
        return ffi.load("crypto")
    end
end)
if not load_ok then
    error("Failed to load OpenSSL libcrypto: " .. tostring(load_err))
end
libcrypto = load_err

ffi.cdef[[
    typedef struct evp_pkey_st EVP_PKEY;
    typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
    typedef struct evp_cipher_st EVP_CIPHER;
    typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
    typedef struct evp_md_ctx_st EVP_MD_CTX;
    typedef struct evp_md_st EVP_MD;

    EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, void *engine);
    EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, void *engine);
    void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
    int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
    int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
    void EVP_PKEY_free(EVP_PKEY *pkey);
    EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, void *engine, const unsigned char *key, size_t keylen);
    EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, void *engine, const unsigned char *key, size_t keylen);
    int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv, size_t *len);
    int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len);
    int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
    int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
    int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

    EVP_MD_CTX *EVP_MD_CTX_new(void);
    void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
    int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, void *engine, EVP_PKEY *pkey);
    int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
    int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, void *engine, EVP_PKEY *pkey);
    int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);
    int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, void *engine);
    const EVP_MD *EVP_sha256(void);

    EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
    const EVP_CIPHER *EVP_aes_256_gcm(void);
    int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, void *impl, const unsigned char *key, const unsigned char *iv);
    int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
    int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, void *impl, const unsigned char *key, const unsigned char *iv);
    int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
    int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

    int RAND_bytes(unsigned char *buf, int num);
]]

local NID_X25519  = 1034
local NID_ED25519 = 1087
local EVP_CTRL_GCM_GET_TAG = 0x10
local EVP_CTRL_GCM_SET_TAG = 0x11

-- ---------------------------------------------------------------------------
-- Encoding helpers
-- ---------------------------------------------------------------------------

local function to_hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function from_hex(h)
    return (h:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
end

-- ---------------------------------------------------------------------------
-- Low-level primitives
-- ---------------------------------------------------------------------------

local function random_bytes(n)
    local buf = ffi.new("unsigned char[?]", n)
    if libcrypto.RAND_bytes(buf, n) ~= 1 then
        error("RAND_bytes failed")
    end
    return ffi.string(buf, n)
end

local function sha256_raw(data)
    local md = ffi.new("unsigned char[32]")
    local mdlen = ffi.new("unsigned int[1]", 32)
    if libcrypto.EVP_Digest(data, #data, md, mdlen, libcrypto.EVP_sha256(), nil) ~= 1 then
        error("EVP_Digest(SHA-256) failed")
    end
    return ffi.string(md, 32)
end

local function sha256_hex(data)
    return to_hex(sha256_raw(data))
end

-- Manual HMAC-SHA256 (RFC 2104) built on EVP_Digest; avoids deprecated HMAC().
local function hmac_sha256(key, msg)
    local block = 64
    if #key > block then
        key = sha256_raw(key)
    end
    key = key .. string.rep("\0", block - #key)
    local ipad, opad = {}, {}
    for i = 1, block do
        local b = key:byte(i)
        ipad[i] = string.char(bit.band(bit.bxor(b, 0x36), 0xFF))
        opad[i] = string.char(bit.band(bit.bxor(b, 0x5C), 0xFF))
    end
    local inner = sha256_raw(table.concat(ipad) .. msg)
    return sha256_raw(table.concat(opad) .. inner)
end

-- HKDF-SHA256 extract + expand (RFC 5869)
local function hkdf(salt, ikm, info, length)
    local prk = hmac_sha256(salt, ikm)
    local t, okm, i = "", "", 0
    while #okm < length do
        i = i + 1
        t = hmac_sha256(prk, t .. info .. string.char(i))
        okm = okm .. t
    end
    return okm:sub(1, length)
end

local function gen_x25519()
    local ctx = libcrypto.EVP_PKEY_CTX_new_id(NID_X25519, nil)
    if libcrypto.EVP_PKEY_keygen_init(ctx) ~= 1 then
        libcrypto.EVP_PKEY_CTX_free(ctx)
        error("EVP_PKEY_keygen_init(X25519) failed")
    end
    local ppkey = ffi.new("EVP_PKEY*[1]")
    if libcrypto.EVP_PKEY_keygen(ctx, ppkey) ~= 1 then
        libcrypto.EVP_PKEY_CTX_free(ctx)
        error("EVP_PKEY_keygen(X25519) failed")
    end
    libcrypto.EVP_PKEY_CTX_free(ctx)
    local pkey = ppkey[0]
    local buf = ffi.new("unsigned char[32]")
    local len = ffi.new("size_t[1]", 32)
    if libcrypto.EVP_PKEY_get_raw_private_key(pkey, buf, len) ~= 1 then
        libcrypto.EVP_PKEY_free(pkey)
        error("EVP_PKEY_get_raw_private_key(X25519) failed")
    end
    local priv = ffi.string(buf, 32)
    if libcrypto.EVP_PKEY_get_raw_public_key(pkey, buf, len) ~= 1 then
        libcrypto.EVP_PKEY_free(pkey)
        error("EVP_PKEY_get_raw_public_key(X25519) failed")
    end
    local pub = ffi.string(buf, 32)
    libcrypto.EVP_PKEY_free(pkey)
    return { public = to_hex(pub), private = to_hex(priv) }
end

local function pub_from_priv(priv_hex)
    local priv = from_hex(priv_hex)
    local pkey = libcrypto.EVP_PKEY_new_raw_private_key(NID_X25519, nil, priv, #priv)
    if pkey == nil then error("EVP_PKEY_new_raw_private_key(X25519) failed") end
    local buf = ffi.new("unsigned char[32]")
    local len = ffi.new("size_t[1]", 32)
    if libcrypto.EVP_PKEY_get_raw_public_key(pkey, buf, len) ~= 1 then
        libcrypto.EVP_PKEY_free(pkey)
        error("EVP_PKEY_get_raw_public_key(X25519) failed")
    end
    local pub = ffi.string(buf, 32)
    libcrypto.EVP_PKEY_free(pkey)
    return to_hex(pub)
end

-- X25519 DH: shared = X25519(priv, peer_pub). Returns raw 32 bytes.
local function x25519(priv_hex, peer_pub_hex)
    local priv = from_hex(priv_hex)
    local peer = from_hex(peer_pub_hex)
    local pkey = libcrypto.EVP_PKEY_new_raw_private_key(NID_X25519, nil, priv, #priv)
    local peerkey = libcrypto.EVP_PKEY_new_raw_public_key(NID_X25519, nil, peer, #peer)
    if pkey == nil or peerkey == nil then
        if pkey then libcrypto.EVP_PKEY_free(pkey) end
        if peerkey then libcrypto.EVP_PKEY_free(peerkey) end
        error("invalid X25519 key material")
    end
    local ctx = libcrypto.EVP_PKEY_CTX_new(pkey, nil)
    local ok = ctx ~= nil
        and libcrypto.EVP_PKEY_derive_init(ctx) == 1
        and libcrypto.EVP_PKEY_derive_set_peer(ctx, peerkey) == 1
    local out = ffi.new("unsigned char[32]")
    local outlen = ffi.new("size_t[1]", 32)
    if not ok or libcrypto.EVP_PKEY_derive(ctx, out, outlen) ~= 1 then
        libcrypto.EVP_PKEY_CTX_free(ctx)
        libcrypto.EVP_PKEY_free(pkey)
        libcrypto.EVP_PKEY_free(peerkey)
        error("EVP_PKEY_derive(X25519) failed")
    end
    libcrypto.EVP_PKEY_CTX_free(ctx)
    libcrypto.EVP_PKEY_free(pkey)
    libcrypto.EVP_PKEY_free(peerkey)
    local shared = ffi.string(out, 32)
    -- Reject all-zero output (small-subpoint / contributory-behaviour failure)
    if shared == string.rep("\0", 32) then
        error("X25519 produced all-zero shared secret")
    end
    return shared
end

local function gen_ed25519()
    local ctx = libcrypto.EVP_PKEY_CTX_new_id(NID_ED25519, nil)
    if libcrypto.EVP_PKEY_keygen_init(ctx) ~= 1 then
        libcrypto.EVP_PKEY_CTX_free(ctx)
        error("EVP_PKEY_keygen_init(Ed25519) failed")
    end
    local ppkey = ffi.new("EVP_PKEY*[1]")
    if libcrypto.EVP_PKEY_keygen(ctx, ppkey) ~= 1 then
        libcrypto.EVP_PKEY_CTX_free(ctx)
        error("EVP_PKEY_keygen(Ed25519) failed")
    end
    libcrypto.EVP_PKEY_CTX_free(ctx)
    local pkey = ppkey[0]
    local buf = ffi.new("unsigned char[32]")
    local len = ffi.new("size_t[1]", 32)
    if libcrypto.EVP_PKEY_get_raw_private_key(pkey, buf, len) ~= 1 then
        libcrypto.EVP_PKEY_free(pkey)
        error("EVP_PKEY_get_raw_private_key(Ed25519) failed")
    end
    local priv = ffi.string(buf, 32)
    if libcrypto.EVP_PKEY_get_raw_public_key(pkey, buf, len) ~= 1 then
        libcrypto.EVP_PKEY_free(pkey)
        error("EVP_PKEY_get_raw_public_key(Ed25519) failed")
    end
    local pub = ffi.string(buf, 32)
    libcrypto.EVP_PKEY_free(pkey)
    return { public = to_hex(pub), private = to_hex(priv) }
end

-- Sign raw message bytes with an Ed25519 private key (hex). Returns hex signature.
local function ed25519_sign(priv_hex, msg)
    local priv = from_hex(priv_hex)
    local pkey = libcrypto.EVP_PKEY_new_raw_private_key(NID_ED25519, nil, priv, #priv)
    if pkey == nil then error("EVP_PKEY_new_raw_private_key(Ed25519) failed") end
    local mdctx = libcrypto.EVP_MD_CTX_new()
    local ok = mdctx ~= nil
        and libcrypto.EVP_DigestSignInit(mdctx, nil, nil, nil, pkey) == 1
    local sig = ffi.new("unsigned char[64]")
    local siglen = ffi.new("size_t[1]", 64)
    if not ok or libcrypto.EVP_DigestSign(mdctx, sig, siglen, msg, #msg) ~= 1 then
        if mdctx then libcrypto.EVP_MD_CTX_free(mdctx) end
        libcrypto.EVP_PKEY_free(pkey)
        error("EVP_DigestSign(Ed25519) failed")
    end
    local signature = ffi.string(sig, siglen[0])
    libcrypto.EVP_MD_CTX_free(mdctx)
    libcrypto.EVP_PKEY_free(pkey)
    return to_hex(signature)
end

-- Verify an Ed25519 signature (hex) over raw message bytes. Returns boolean.
local function ed25519_verify(pub_hex, msg, sig_hex)
    local ok, valid = pcall(function()
        local pub = from_hex(pub_hex)
        local sig = from_hex(sig_hex)
        local pkey = libcrypto.EVP_PKEY_new_raw_public_key(NID_ED25519, nil, pub, #pub)
        if pkey == nil then return false end
        local mdctx = libcrypto.EVP_MD_CTX_new()
        local init_ok = mdctx ~= nil
            and libcrypto.EVP_DigestVerifyInit(mdctx, nil, nil, nil, pkey) == 1
        local rc = libcrypto.EVP_DigestVerify(mdctx, sig, #sig, msg, #msg)
        if mdctx then libcrypto.EVP_MD_CTX_free(mdctx) end
        libcrypto.EVP_PKEY_free(pkey)
        return init_ok and rc == 1
    end)
    return ok and valid or false
end

-- AES-256-GCM encrypt. key is raw 32 bytes; aad is an arbitrary string.
-- Returns { nonce = hex, ct = hex, tag = hex }.
local function aes_gcm_encrypt(key, plaintext, aad)
    local nonce = random_bytes(12)
    local ctx = libcrypto.EVP_CIPHER_CTX_new()
    if ctx == nil then error("EVP_CIPHER_CTX_new failed") end
    local ok = libcrypto.EVP_EncryptInit_ex(ctx, libcrypto.EVP_aes_256_gcm(), nil, key, nonce) == 1
    local olen = ffi.new("int[1]")
    if ok and aad and #aad > 0 then
        ok = libcrypto.EVP_EncryptUpdate(ctx, nil, olen, aad, #aad) == 1
    end
    local buf = ffi.new("unsigned char[?]", #plaintext + 16)
    local outl = ffi.new("int[1]")
    if ok then
        ok = libcrypto.EVP_EncryptUpdate(ctx, buf, outl, plaintext, #plaintext) == 1
    end
    local ct_len = outl[0]
    if ok then
        ok = libcrypto.EVP_EncryptFinal_ex(ctx, buf + ct_len, outl) == 1
    end
    ct_len = ct_len + outl[0]
    local tag = ffi.new("unsigned char[16]")
    if ok then
        ok = libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1
    end
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    if not ok then error("AES-256-GCM encryption failed") end
    return {
        nonce = to_hex(nonce),
        ct = to_hex(ffi.string(buf, ct_len)),
        tag = to_hex(ffi.string(tag, 16))
    }
end

-- AES-256-GCM decrypt with authentication. Returns plaintext or nil on tag failure.
local function aes_gcm_decrypt(key, nonce_hex, ct_hex, tag_hex, aad)
    local ok, result = pcall(function()
        local nonce = from_hex(nonce_hex)
        local ct = from_hex(ct_hex)
        local tag = from_hex(tag_hex)
        local ctx = libcrypto.EVP_CIPHER_CTX_new()
        if ctx == nil then return nil end
        local init_ok = libcrypto.EVP_DecryptInit_ex(ctx, libcrypto.EVP_aes_256_gcm(), nil, key, nonce) == 1
        local olen = ffi.new("int[1]")
        if init_ok and aad and #aad > 0 then
            init_ok = libcrypto.EVP_DecryptUpdate(ctx, nil, olen, aad, #aad) == 1
        end
        local buf = ffi.new("unsigned char[?]", #ct + 16)
        local outl = ffi.new("int[1]")
        local pt_len = 0
        if init_ok then
            init_ok = libcrypto.EVP_DecryptUpdate(ctx, buf, outl, ct, #ct) == 1
            pt_len = outl[0]
        end
        if init_ok then
            local tagbuf = ffi.new("unsigned char[16]", tag)
            libcrypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagbuf)
        end
        local final_ok = init_ok
            and libcrypto.EVP_DecryptFinal_ex(ctx, buf + pt_len, outl) == 1
        pt_len = pt_len + outl[0]
        libcrypto.EVP_CIPHER_CTX_free(ctx)
        if not final_ok then return nil end
        return ffi.string(buf, pt_len)
    end)
    return ok and result or nil
end

-- ---------------------------------------------------------------------------
-- CryptoManager: per-client identity, signed prekey, one-time prekeys, X3DH
-- ---------------------------------------------------------------------------

local X3DH_INFO = "E2EEChat-X3DH"
local F_PREFIX  = string.rep("\xff", 32) -- domain separation prefix (X25519, per Signal spec)
local ZERO_SALT = string.rep("\0", 32)

local CryptoManager = {}
CryptoManager.__index = CryptoManager

function CryptoManager.new()
    local self = setmetatable({}, CryptoManager)
    self.identity_key = gen_x25519()          -- IK  (X25519)
    self.signed_prekey = gen_x25519()         -- SPK (X25519)
    self.ed25519 = gen_ed25519()              -- Ed25519 signing key bound to identity
    self.signed_prekey.signature = ed25519_sign(self.ed25519.private, from_hex(self.signed_prekey.public))
    self.one_time_prekeys = {}
    for i = 1, 5 do
        local opk = gen_x25519()
        opk.id = i
        self.one_time_prekeys[i] = opk
    end
    return self
end

-- Bundle uploaded to the server (public material only)
function CryptoManager:get_upload_bundle()
    local opks = {}
    for _, o in ipairs(self.one_time_prekeys) do
        opks[#opks + 1] = { id = o.id, pub = o.public }
    end
    return {
        ik = self.identity_key.public,
        spk = self.signed_prekey.public,
        spk_sig = self.signed_prekey.signature,
        ed_id = self.ed25519.public,
        opks = opks
    }
end

function CryptoManager:get_opk_priv(id)
    for _, o in ipairs(self.one_time_prekeys) do
        if o.id == id then return o.private end
    end
    return nil
end

-- X3DH initiator (Alice). Verifies the SPK signature, derives SK.
-- Returns SK (raw 32 bytes), ephemeral_pub (hex).
function CryptoManager:x3dh_initiator(bundle)
    if type(bundle) ~= "table"
        or type(bundle.ik) ~= "string" or type(bundle.spk) ~= "string"
        or type(bundle.spk_sig) ~= "string" or type(bundle.ed_id) ~= "string" then
        error("malformed prekey bundle")
    end
    if not ed25519_verify(bundle.ed_id, from_hex(bundle.spk), bundle.spk_sig) then
        error("signed prekey signature verification failed (possible MITM)")
    end
    local ek = gen_x25519()
    local dh1 = x25519(self.identity_key.private, bundle.spk)   -- DH(IK_A, SPK_B)
    local dh2 = x25519(ek.private, bundle.ik)                   -- DH(EK_A, IK_B)
    local dh3 = x25519(ek.private, bundle.spk)                  -- DH(EK_A, SPK_B)
    local dh4 = ""
    if bundle.opk and bundle.opk.pub then                       -- DH(EK_A, OPK_B) [optional]
        dh4 = x25519(ek.private, bundle.opk.pub)
    end
    local ikm = F_PREFIX .. dh1 .. dh2 .. dh3 .. dh4
    local sk = hkdf(ZERO_SALT, ikm, X3DH_INFO, 32)
    return sk, ek.public
end

-- X3DH receiver (Bob). Derives the same SK from his private keys and the
-- initiator's public keys carried in the first message.
function CryptoManager:x3dh_receiver(my_ik_priv, my_spk_priv, my_opk_priv, peer_ik, peer_ek)
    local dh1 = x25519(my_spk_priv, peer_ik)                    -- DH(SPK_B, IK_A)
    local dh2 = x25519(my_ik_priv, peer_ek)                     -- DH(IK_B, EK_A)
    local dh3 = x25519(my_spk_priv, peer_ek)                    -- DH(SPK_B, EK_A)
    local dh4 = ""
    if my_opk_priv then                                         -- DH(OPK_B, EK_A) [optional]
        dh4 = x25519(my_opk_priv, peer_ek)
    end
    local ikm = F_PREFIX .. dh1 .. dh2 .. dh3 .. dh4
    return hkdf(ZERO_SALT, ikm, X3DH_INFO, 32)
end

-- ---------------------------------------------------------------------------
-- Module exports
-- ---------------------------------------------------------------------------

local M = {
    new = CryptoManager.new,
    random_bytes = random_bytes,
    sha256_raw = sha256_raw,
    sha256_hex = sha256_hex,
    hmac_sha256 = hmac_sha256,
    hkdf = hkdf,
    gen_x25519 = gen_x25519,
    pub_from_priv = pub_from_priv,
    x25519 = x25519,
    gen_ed25519 = gen_ed25519,
    ed25519_sign = ed25519_sign,
    ed25519_verify = ed25519_verify,
    aes_gcm_encrypt = aes_gcm_encrypt,
    aes_gcm_decrypt = aes_gcm_decrypt,
    to_hex = to_hex,
    from_hex = from_hex,
}
M.__index = M

setmetatable(CryptoManager, M)

return M
