module.exports = [
"[project]/src/lib/pq-kem-real.ts [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "MLKEM768KEM",
    ()=>MLKEM768KEM,
    "ML_KEM_CIPHERTEXT_LEN",
    ()=>ML_KEM_CIPHERTEXT_LEN,
    "getActiveKEM",
    ()=>getActiveKEM,
    "isKemWrappedKey",
    ()=>isKemWrappedKey
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$ml$2d$kem$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/post-quantum/ml-kem.js [app-ssr] (ecmascript)");
;
const ML_KEM_CIPHERTEXT_LEN = 1088;
const AES_KEY_LEN = 32;
const GCM_IV_LEN = 12;
const GCM_TAG_LEN = 16;
class MLKEM768KEM {
    generateKeyPair() {
        const { secretKey, publicKey } = __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$ml$2d$kem$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["ml_kem768"].keygen();
        return {
            publicKey,
            privateKey: secretKey
        };
    }
    encapsulate(publicKey) {
        const { cipherText, sharedSecret } = __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$ml$2d$kem$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["ml_kem768"].encapsulate(publicKey);
        return {
            ciphertext: cipherText,
            sharedSecret
        };
    }
    decapsulate(privateKey, ciphertext) {
        return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$ml$2d$kem$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["ml_kem768"].decapsulate(privateKey, ciphertext);
    }
    async sharedSecretToAesKey(sharedSecret) {
        const hash = await crypto.subtle.digest("SHA-256", sharedSecret);
        return crypto.subtle.importKey("raw", hash, {
            name: "AES-GCM",
            length: 256
        }, false, [
            "encrypt",
            "decrypt"
        ]);
    }
    /**
   * Hybrid KEM wrap: ML-KEM encapsulate + AES-GCM encrypt the raw AES key.
   * Output: base64( kemCiphertext[1088] | iv[12] | aesCiphertext[32+16] )
   * Total: 1148 bytes → base64 ≈ 1531 chars
   */ async wrapAesKey(rawAesKey, recipientMlKemPublicKey) {
        const { ciphertext: kemCt, sharedSecret } = this.encapsulate(recipientMlKemPublicKey);
        const aesKey = await this.sharedSecretToAesKey(sharedSecret);
        const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_LEN));
        const encrypted = await crypto.subtle.encrypt({
            name: "AES-GCM",
            iv: iv
        }, aesKey, rawAesKey);
        const combined = new Uint8Array(kemCt.length + iv.length + encrypted.byteLength);
        combined.set(kemCt, 0);
        combined.set(iv, kemCt.length);
        combined.set(new Uint8Array(encrypted), kemCt.length + iv.length);
        return btoa(String.fromCharCode(...combined));
    }
    /**
   * Hybrid KEM unwrap: split → ML-KEM decapsulate → AES-GCM decrypt.
   */ async unwrapAesKey(wrappedKeyB64, recipientMlKemPrivateKey) {
        const combined = Uint8Array.from(atob(wrappedKeyB64), (c)=>c.charCodeAt(0));
        const kemCt = combined.slice(0, ML_KEM_CIPHERTEXT_LEN);
        const iv = combined.slice(ML_KEM_CIPHERTEXT_LEN, ML_KEM_CIPHERTEXT_LEN + GCM_IV_LEN);
        const aesCt = combined.slice(ML_KEM_CIPHERTEXT_LEN + GCM_IV_LEN);
        const sharedSecret = this.decapsulate(recipientMlKemPrivateKey, kemCt);
        const aesKey = await this.sharedSecretToAesKey(sharedSecret);
        const decrypted = await crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: iv
        }, aesKey, aesCt);
        return new Uint8Array(decrypted);
    }
}
function getActiveKEM() {
    return new MLKEM768KEM();
}
function isKemWrappedKey(wrappedKeyB64) {
    try {
        const decoded = Uint8Array.from(atob(wrappedKeyB64), (c)=>c.charCodeAt(0));
        return decoded.length >= ML_KEM_CIPHERTEXT_LEN;
    } catch  {
        return false;
    }
}
;
}),
"[project]/node_modules/@noble/hashes/_u64.js [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "add",
    ()=>add,
    "add3H",
    ()=>add3H,
    "add3L",
    ()=>add3L,
    "add4H",
    ()=>add4H,
    "add4L",
    ()=>add4L,
    "add5H",
    ()=>add5H,
    "add5L",
    ()=>add5L,
    "default",
    ()=>__TURBOPACK__default__export__,
    "fromBig",
    ()=>fromBig,
    "rotlBH",
    ()=>rotlBH,
    "rotlBL",
    ()=>rotlBL,
    "rotlSH",
    ()=>rotlSH,
    "rotlSL",
    ()=>rotlSL,
    "rotr32H",
    ()=>rotr32H,
    "rotr32L",
    ()=>rotr32L,
    "rotrBH",
    ()=>rotrBH,
    "rotrBL",
    ()=>rotrBL,
    "rotrSH",
    ()=>rotrSH,
    "rotrSL",
    ()=>rotrSL,
    "shrSH",
    ()=>shrSH,
    "shrSL",
    ()=>shrSL,
    "split",
    ()=>split,
    "toBig",
    ()=>toBig
]);
const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n = /* @__PURE__ */ BigInt(32);
// Split bigint into two 32-bit halves. With `le=true`, returned fields become `{ h: low, l: high
// }` to match little-endian word order rather than the property names.
function fromBig(n, le = false) {
    if (le) return {
        h: Number(n & U32_MASK64),
        l: Number(n >> _32n & U32_MASK64)
    };
    return {
        h: Number(n >> _32n & U32_MASK64) | 0,
        l: Number(n & U32_MASK64) | 0
    };
}
// Split bigint list into `[highWords, lowWords]` when `le=false`; with `le=true`, the first array
// holds the low halves because `fromBig(...)` swaps the semantic meaning of `h` and `l`.
function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for(let i = 0; i < len; i++){
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [
            h,
            l
        ];
    }
    return [
        Ah,
        Al
    ];
}
// Combine explicit `(high, low)` 32-bit halves into a bigint; `>>> 0` normalizes signed JS
// bitwise results back to uint32 first, and little-endian callers must swap.
const toBig = (h, l)=>BigInt(h >>> 0) << _32n | BigInt(l >>> 0);
// High 32-bit half of a 64-bit logical right shift for `s` in `0..31`.
const shrSH = (h, _l, s)=>h >>> s;
// Low 32-bit half of a 64-bit logical right shift, valid for `s` in `1..31`.
const shrSL = (h, l, s)=>h << 32 - s | l >>> s;
// High 32-bit half of a 64-bit right rotate, valid for `s` in `1..31`.
const rotrSH = (h, l, s)=>h >>> s | l << 32 - s;
// Low 32-bit half of a 64-bit right rotate, valid for `s` in `1..31`.
const rotrSL = (h, l, s)=>h << 32 - s | l >>> s;
// High 32-bit half of a 64-bit right rotate, valid for `s` in `33..63`; `32` uses `rotr32*`.
const rotrBH = (h, l, s)=>h << 64 - s | l >>> s - 32;
// Low 32-bit half of a 64-bit right rotate, valid for `s` in `33..63`; `32` uses `rotr32*`.
const rotrBL = (h, l, s)=>h >>> s - 32 | l << 64 - s;
// High 32-bit half of a 64-bit right rotate for `s === 32`; this is just the swapped low half.
const rotr32H = (_h, l)=>l;
// Low 32-bit half of a 64-bit right rotate for `s === 32`; this is just the swapped high half.
const rotr32L = (h, _l)=>h;
// High 32-bit half of a 64-bit left rotate, valid for `s` in `1..31`.
const rotlSH = (h, l, s)=>h << s | l >>> 32 - s;
// Low 32-bit half of a 64-bit left rotate, valid for `s` in `1..31`.
const rotlSL = (h, l, s)=>l << s | h >>> 32 - s;
// High 32-bit half of a 64-bit left rotate, valid for `s` in `33..63`; `32` uses `rotr32*`.
const rotlBH = (h, l, s)=>l << s - 32 | h >>> 64 - s;
// Low 32-bit half of a 64-bit left rotate, valid for `s` in `33..63`; `32` uses `rotr32*`.
const rotlBL = (h, l, s)=>h << s - 32 | l >>> 64 - s;
// Add two split 64-bit words and return the split `{ h, l }` sum.
// JS uses 32-bit signed integers for bitwise operations, so we cannot simply shift the carry out
// of the low sum and instead use division.
function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return {
        h: Ah + Bh + (l / 2 ** 32 | 0) | 0,
        l: l | 0
    };
}
// Addition with more than 2 elements
// Unmasked low-word accumulator for 3-way addition; pass the raw result into `add3H(...)`.
const add3L = (Al, Bl, Cl)=>(Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
// High-word finalize step for 3-way addition; `low` must be the untruncated output of `add3L(...)`.
const add3H = (low, Ah, Bh, Ch)=>Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
// Unmasked low-word accumulator for 4-way addition; pass the raw result into `add4H(...)`.
const add4L = (Al, Bl, Cl, Dl)=>(Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
// High-word finalize step for 4-way addition; `low` must be the untruncated output of `add4L(...)`.
const add4H = (low, Ah, Bh, Ch, Dh)=>Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
// Unmasked low-word accumulator for 5-way addition; pass the raw result into `add5H(...)`.
const add5L = (Al, Bl, Cl, Dl, El)=>(Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
// High-word finalize step for 5-way addition; `low` must be the untruncated output of `add5L(...)`.
const add5H = (low, Ah, Bh, Ch, Dh, Eh)=>Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
;
// Canonical grouped namespace for callers that prefer one object.
// Named exports stay for direct imports.
// prettier-ignore
const u64 = {
    fromBig,
    split,
    toBig,
    shrSH,
    shrSL,
    rotrSH,
    rotrSL,
    rotrBH,
    rotrBL,
    rotr32H,
    rotr32L,
    rotlSH,
    rotlSL,
    rotlBH,
    rotlBL,
    add,
    add3L,
    add3H,
    add4L,
    add4H,
    add5H,
    add5L
};
const __TURBOPACK__default__export__ = u64;
 //# sourceMappingURL=_u64.js.map
}),
"[project]/node_modules/@noble/hashes/utils.js [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

/**
 * Checks if something is Uint8Array. Be careful: nodejs Buffer will return true.
 * @param a - value to test
 * @returns `true` when the value is a Uint8Array-compatible view.
 * @example
 * Check whether a value is a Uint8Array-compatible view.
 * ```ts
 * isBytes(new Uint8Array([1, 2, 3]));
 * ```
 */ __turbopack_context__.s([
    "abytes",
    ()=>abytes,
    "aexists",
    ()=>aexists,
    "ahash",
    ()=>ahash,
    "anumber",
    ()=>anumber,
    "aoutput",
    ()=>aoutput,
    "asyncLoop",
    ()=>asyncLoop,
    "byteSwap",
    ()=>byteSwap,
    "byteSwap32",
    ()=>byteSwap32,
    "bytesToHex",
    ()=>bytesToHex,
    "checkOpts",
    ()=>checkOpts,
    "clean",
    ()=>clean,
    "concatBytes",
    ()=>concatBytes,
    "copyBytes",
    ()=>copyBytes,
    "createHasher",
    ()=>createHasher,
    "createView",
    ()=>createView,
    "hexToBytes",
    ()=>hexToBytes,
    "isBytes",
    ()=>isBytes,
    "isLE",
    ()=>isLE,
    "kdfInputToBytes",
    ()=>kdfInputToBytes,
    "nextTick",
    ()=>nextTick,
    "oidNist",
    ()=>oidNist,
    "randomBytes",
    ()=>randomBytes,
    "rotl",
    ()=>rotl,
    "rotr",
    ()=>rotr,
    "swap32IfBE",
    ()=>swap32IfBE,
    "swap8IfBE",
    ()=>swap8IfBE,
    "u32",
    ()=>u32,
    "u8",
    ()=>u8,
    "utf8ToBytes",
    ()=>utf8ToBytes
]);
function isBytes(a) {
    // Plain `instanceof Uint8Array` is too strict for some Buffer / proxy / cross-realm cases.
    // The fallback still requires a real ArrayBuffer view, so plain
    // JSON-deserialized `{ constructor: ... }` spoofing is rejected, and
    // `BYTES_PER_ELEMENT === 1` keeps the fallback on byte-oriented views.
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array' && 'BYTES_PER_ELEMENT' in a && a.BYTES_PER_ELEMENT === 1;
}
function anumber(n, title = '') {
    if (typeof n !== 'number') {
        const prefix = title && `"${title}" `;
        throw new TypeError(`${prefix}expected number, got ${typeof n}`);
    }
    if (!Number.isSafeInteger(n) || n < 0) {
        const prefix = title && `"${title}" `;
        throw new RangeError(`${prefix}expected integer >= 0, got ${n}`);
    }
}
function abytes(value, length, title = '') {
    const bytes = isBytes(value);
    const len = value?.length;
    const needsLen = length !== undefined;
    if (!bytes || needsLen && len !== length) {
        const prefix = title && `"${title}" `;
        const ofLen = needsLen ? ` of length ${length}` : '';
        const got = bytes ? `length=${len}` : `type=${typeof value}`;
        const message = prefix + 'expected Uint8Array' + ofLen + ', got ' + got;
        if (!bytes) throw new TypeError(message);
        throw new RangeError(message);
    }
    return value;
}
function copyBytes(bytes) {
    // `Uint8Array.from(...)` would also accept arrays / other typed arrays. Keep this helper strict
    // because callers use it at byte-validation boundaries before mutating the detached copy.
    return Uint8Array.from(abytes(bytes));
}
function ahash(h) {
    if (typeof h !== 'function' || typeof h.create !== 'function') throw new TypeError('Hash must wrapped by utils.createHasher');
    anumber(h.outputLen);
    anumber(h.blockLen);
    // HMAC and KDF callers treat these as real byte lengths; allowing zero lets fake wrappers pass
    // validation and can produce empty outputs instead of failing fast.
    if (h.outputLen < 1) throw new Error('"outputLen" must be >= 1');
    if (h.blockLen < 1) throw new Error('"blockLen" must be >= 1');
}
function aexists(instance, checkFinished = true) {
    if (instance.destroyed) throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished) throw new Error('Hash#digest() has already been called');
}
function aoutput(out, instance) {
    abytes(out, undefined, 'digestInto() output');
    const min = instance.outputLen;
    if (out.length < min) {
        throw new RangeError('"digestInto() output" expected to be of length >=' + min);
    }
}
function u8(arr) {
    return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
    for(let i = 0; i < arrays.length; i++){
        arrays[i].fill(0);
    }
}
function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
    return word << 32 - shift | word >>> shift;
}
function rotl(word, shift) {
    return word << shift | word >>> 32 - shift >>> 0;
}
const isLE = /* @__PURE__ */ (()=>new Uint8Array(new Uint32Array([
        0x11223344
    ]).buffer)[0] === 0x44)();
function byteSwap(word) {
    return word << 24 & 0xff000000 | word << 8 & 0xff0000 | word >>> 8 & 0xff00 | word >>> 24 & 0xff;
}
const swap8IfBE = isLE ? (n)=>n : (n)=>byteSwap(n) >>> 0;
function byteSwap32(arr) {
    for(let i = 0; i < arr.length; i++){
        arr[i] = byteSwap(arr[i]);
    }
    return arr;
}
const swap32IfBE = isLE ? (u)=>u : byteSwap32;
// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const hasHexBuiltin = /* @__PURE__ */ (()=>// @ts-ignore
    typeof Uint8Array.from([]).toHex === 'function' && typeof Uint8Array.fromHex === 'function')();
// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({
    length: 256
}, (_, i)=>i.toString(16).padStart(2, '0'));
function bytesToHex(bytes) {
    abytes(bytes);
    // @ts-ignore
    if (hasHexBuiltin) return bytes.toHex();
    // pre-caching improves the speed 6x
    let hex = '';
    for(let i = 0; i < bytes.length; i++){
        hex += hexes[bytes[i]];
    }
    return hex;
}
// We use optimized technique to convert hex string to byte array
const asciis = {
    _0: 48,
    _9: 57,
    A: 65,
    F: 70,
    a: 97,
    f: 102
};
function asciiToBase16(ch) {
    if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0; // '2' => 50-48
    if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10); // 'B' => 66-(65-10)
    if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10); // 'b' => 98-(97-10)
    return;
}
function hexToBytes(hex) {
    if (typeof hex !== 'string') throw new TypeError('hex string expected, got ' + typeof hex);
    if (hasHexBuiltin) {
        try {
            return Uint8Array.fromHex(hex);
        } catch (error) {
            if (error instanceof SyntaxError) throw new RangeError(error.message);
            throw error;
        }
    }
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2) throw new RangeError('hex string expected, got unpadded hex of length ' + hl);
    const array = new Uint8Array(al);
    for(let ai = 0, hi = 0; ai < al; ai++, hi += 2){
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new RangeError('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
    }
    return array;
}
const nextTick = async ()=>{};
async function asyncLoop(iters, tick, cb) {
    let ts = Date.now();
    for(let i = 0; i < iters; i++){
        cb(i);
        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick) continue;
        await nextTick();
        ts += diff;
    }
}
function utf8ToBytes(str) {
    if (typeof str !== 'string') throw new TypeError('string expected');
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
function kdfInputToBytes(data, errorTitle = '') {
    if (typeof data === 'string') return utf8ToBytes(data);
    return abytes(data, undefined, errorTitle);
}
function concatBytes(...arrays) {
    let sum = 0;
    for(let i = 0; i < arrays.length; i++){
        const a = arrays[i];
        abytes(a);
        sum += a.length;
    }
    const res = new Uint8Array(sum);
    for(let i = 0, pad = 0; i < arrays.length; i++){
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
    }
    return res;
}
function checkOpts(defaults, opts) {
    if (opts !== undefined && ({}).toString.call(opts) !== '[object Object]') throw new TypeError('options must be object or undefined');
    const merged = Object.assign(defaults, opts);
    return merged;
}
function createHasher(hashCons, info = {}) {
    const hashC = (msg, opts)=>hashCons(opts).update(msg).digest();
    const tmp = hashCons(undefined);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.canXOF = tmp.canXOF;
    hashC.create = (opts)=>hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
}
function randomBytes(bytesLength = 32) {
    // Match the repo's other length-taking helpers instead of relying on Uint8Array coercion.
    anumber(bytesLength, 'bytesLength');
    const cr = typeof globalThis === 'object' ? globalThis.crypto : null;
    if (typeof cr?.getRandomValues !== 'function') throw new Error('crypto.getRandomValues must be defined');
    // Web Cryptography API Level 2 §10.1.1:
    // if `byteLength > 65536`, throw `QuotaExceededError`.
    // Keep the guard explicit so callers can see the quota in code
    // instead of discovering it by reading the spec or host errors.
    // This wrapper surfaces the same quota as a stable library RangeError.
    if (bytesLength > 65536) throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
    return cr.getRandomValues(new Uint8Array(bytesLength));
}
const oidNist = (suffix)=>({
        // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
        // Larger suffix values would need base-128 OID encoding and a different length byte.
        oid: Uint8Array.from([
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            suffix
        ])
    }); //# sourceMappingURL=utils.js.map
}),
"[project]/node_modules/@noble/hashes/sha3.js [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "Keccak",
    ()=>Keccak,
    "keccakP",
    ()=>keccakP,
    "keccak_224",
    ()=>keccak_224,
    "keccak_256",
    ()=>keccak_256,
    "keccak_384",
    ()=>keccak_384,
    "keccak_512",
    ()=>keccak_512,
    "sha3_224",
    ()=>sha3_224,
    "sha3_256",
    ()=>sha3_256,
    "sha3_384",
    ()=>sha3_384,
    "sha3_512",
    ()=>sha3_512,
    "shake128",
    ()=>shake128,
    "shake128_32",
    ()=>shake128_32,
    "shake256",
    ()=>shake256,
    "shake256_64",
    ()=>shake256_64
]);
/**
 * SHA3 (keccak) hash function, based on a new "Sponge function" design.
 * Different from older hashes, the internal state is bigger than output size.
 *
 * Check out
 * {@link https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf | FIPS-202},
 * {@link https://keccak.team/keccak.html | Website}, and
 * {@link https://crypto.stackexchange.com/q/15727 | the differences between
 * SHA-3 and Keccak}.
 *
 * Check out `sha3-addons` module for cSHAKE, k12, and others.
 * @module
 */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$_u64$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/hashes/_u64.js [app-ssr] (ecmascript)");
// prettier-ignore
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/hashes/utils.js [app-ssr] (ecmascript)");
;
;
// No __PURE__ annotations in sha3 header:
// EVERYTHING is in fact used on every export.
// Various per round constants calculations
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _7n = BigInt(7);
const _256n = BigInt(256);
// FIPS 202 Algorithm 5 rc(): when the outgoing bit is 1, the 8-bit LFSR xors
// taps 0, 4, 5, and 6, which compresses to the feedback mask `0x71`.
const _0x71n = BigInt(0x71);
const SHA3_PI = [];
const SHA3_ROTL = [];
const _SHA3_IOTA = []; // no pure annotation: var is always used
for(let round = 0, R = _1n, x = 1, y = 0; round < 24; round++){
    // Pi
    [x, y] = [
        y,
        (2 * x + 3 * y) % 5
    ];
    SHA3_PI.push(2 * (5 * y + x));
    // Rotational
    SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
    // Iota
    let t = _0n;
    for(let j = 0; j < 7; j++){
        R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
        if (R & _2n) t ^= _1n << (_1n << BigInt(j)) - _1n;
    }
    _SHA3_IOTA.push(t);
}
const IOTAS = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$_u64$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["split"])(_SHA3_IOTA, true);
// `split(..., true)` keeps the local little-endian lane-word layout used by
// `state32`, so these `H` / `L` tables follow the file's first-word /
// second-word lane slots rather than `_u64.ts`'s usual high/low naming.
const SHA3_IOTA_H = IOTAS[0];
const SHA3_IOTA_L = IOTAS[1];
// Left rotation (without 0, 32, 64)
const rotlH = (h, l, s)=>s > 32 ? (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$_u64$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["rotlBH"])(h, l, s) : (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$_u64$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["rotlSH"])(h, l, s);
const rotlL = (h, l, s)=>s > 32 ? (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$_u64$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["rotlBL"])(h, l, s) : (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$_u64$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["rotlSL"])(h, l, s);
function keccakP(s, rounds = 24) {
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["anumber"])(rounds, 'rounds');
    // This implementation precomputes only the standard Keccak-f[1600] 24-round Iota table.
    if (rounds < 1 || rounds > 24) throw new Error('"rounds" expected integer 1..24');
    const B = new Uint32Array(5 * 2);
    // NOTE: all indices are x2 since we store state as u32 instead of u64 (bigints to slow in js)
    for(let round = 24 - rounds; round < 24; round++){
        // Theta θ
        for(let x = 0; x < 10; x++)B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
        for(let x = 0; x < 10; x += 2){
            const idx1 = (x + 8) % 10;
            const idx0 = (x + 2) % 10;
            const B0 = B[idx0];
            const B1 = B[idx0 + 1];
            const Th = rotlH(B0, B1, 1) ^ B[idx1];
            const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
            for(let y = 0; y < 50; y += 10){
                s[x + y] ^= Th;
                s[x + y + 1] ^= Tl;
            }
        }
        // Rho (ρ) and Pi (π)
        let curH = s[2];
        let curL = s[3];
        for(let t = 0; t < 24; t++){
            const shift = SHA3_ROTL[t];
            const Th = rotlH(curH, curL, shift);
            const Tl = rotlL(curH, curL, shift);
            const PI = SHA3_PI[t];
            curH = s[PI];
            curL = s[PI + 1];
            s[PI] = Th;
            s[PI + 1] = Tl;
        }
        // Chi (χ)
        // Same as:
        // for (let x = 0; x < 10; x++) B[x] = s[y + x];
        // for (let x = 0; x < 10; x++) s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
        for(let y = 0; y < 50; y += 10){
            const b0 = s[y], b1 = s[y + 1], b2 = s[y + 2], b3 = s[y + 3];
            s[y] ^= ~s[y + 2] & s[y + 4];
            s[y + 1] ^= ~s[y + 3] & s[y + 5];
            s[y + 2] ^= ~s[y + 4] & s[y + 6];
            s[y + 3] ^= ~s[y + 5] & s[y + 7];
            s[y + 4] ^= ~s[y + 6] & s[y + 8];
            s[y + 5] ^= ~s[y + 7] & s[y + 9];
            s[y + 6] ^= ~s[y + 8] & b0;
            s[y + 7] ^= ~s[y + 9] & b1;
            s[y + 8] ^= ~b0 & b2;
            s[y + 9] ^= ~b1 & b3;
        }
        // Iota (ι)
        s[0] ^= SHA3_IOTA_H[round];
        s[1] ^= SHA3_IOTA_L[round];
    }
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clean"])(B);
}
class Keccak {
    state;
    pos = 0;
    posOut = 0;
    finished = false;
    state32;
    destroyed = false;
    blockLen;
    suffix;
    outputLen;
    canXOF;
    enableXOF = false;
    rounds;
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24){
        this.blockLen = blockLen;
        this.suffix = suffix;
        this.outputLen = outputLen;
        this.enableXOF = enableXOF;
        this.canXOF = enableXOF;
        this.rounds = rounds;
        // Can be passed from user as dkLen
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["anumber"])(outputLen, 'outputLen');
        // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
        // 0 < blockLen < 200
        if (!(0 < blockLen && blockLen < 200)) throw new Error('only keccak-f1600 function is supported');
        this.state = new Uint8Array(200);
        this.state32 = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["u32"])(this.state);
    }
    clone() {
        return this._cloneInto();
    }
    keccak() {
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["swap32IfBE"])(this.state32);
        keccakP(this.state32, this.rounds);
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["swap32IfBE"])(this.state32);
        this.posOut = 0;
        this.pos = 0;
    }
    update(data) {
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["aexists"])(this);
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(data);
        const { blockLen, state } = this;
        const len = data.length;
        for(let pos = 0; pos < len;){
            const take = Math.min(blockLen - this.pos, len - pos);
            for(let i = 0; i < take; i++)state[this.pos++] ^= data[pos++];
            if (this.pos === blockLen) this.keccak();
        }
        return this;
    }
    finish() {
        if (this.finished) return;
        this.finished = true;
        const { state, suffix, pos, blockLen } = this;
        // FIPS 202 appends the SHA3/SHAKE domain-separation suffix before pad10*1.
        // These byte values already include the first padding bit, while the
        // final `0x80` below supplies the closing `1` bit in the last rate byte.
        state[pos] ^= suffix;
        // If that combined suffix lands in the last rate byte and already sets
        // bit 7, absorb it first so the final pad10*1 bit can be xored into a
        // fresh block.
        if ((suffix & 0x80) !== 0 && pos === blockLen - 1) this.keccak();
        state[blockLen - 1] ^= 0x80;
        this.keccak();
    }
    writeInto(out) {
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["aexists"])(this, false);
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(out);
        this.finish();
        const bufferOut = this.state;
        const { blockLen } = this;
        for(let pos = 0, len = out.length; pos < len;){
            if (this.posOut >= blockLen) this.keccak();
            const take = Math.min(blockLen - this.posOut, len - pos);
            out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
            this.posOut += take;
            pos += take;
        }
        return out;
    }
    xofInto(out) {
        // Plain SHA3/Keccak usage with XOF is probably a mistake, but this base
        // class is also reused by SHAKE/cSHAKE/KMAC/TupleHash/ParallelHash/
        // TurboSHAKE/KangarooTwelve wrappers that intentionally enable XOF.
        if (!this.enableXOF) throw new Error('XOF is not possible for this instance');
        return this.writeInto(out);
    }
    xof(bytes) {
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["anumber"])(bytes);
        return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["aoutput"])(out, this);
        if (this.finished) throw new Error('digest() was already called');
        // `aoutput(...)` allows oversized buffers; digestInto() must fill only the advertised digest.
        this.writeInto(out.subarray(0, this.outputLen));
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.outputLen);
        this.digestInto(out);
        return out;
    }
    destroy() {
        this.destroyed = true;
        (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["clean"])(this.state);
    }
    _cloneInto(to) {
        const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
        to ||= new Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
        // Reused destinations can come from a different rate/capacity variant, so clone must rewrite
        // the sponge geometry as well as the state words.
        to.blockLen = blockLen;
        to.state32.set(this.state32);
        to.pos = this.pos;
        to.posOut = this.posOut;
        to.finished = this.finished;
        to.rounds = rounds;
        // Suffix can change in cSHAKE
        to.suffix = suffix;
        to.outputLen = outputLen;
        to.enableXOF = enableXOF;
        // Clones must preserve the public capability bit too; `_KMAC` reuses this path and deep clone
        // tests compare instance fields directly, so leaving `canXOF` behind makes the clone lie.
        to.canXOF = this.canXOF;
        to.destroyed = this.destroyed;
        return to;
    }
}
const genKeccak = (suffix, blockLen, outputLen, info = {})=>(0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["createHasher"])(()=>new Keccak(blockLen, suffix, outputLen), info);
const sha3_224 = /* @__PURE__ */ genKeccak(0x06, 144, 28, /* @__PURE__ */ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["oidNist"])(0x07));
const sha3_256 = /* @__PURE__ */ genKeccak(0x06, 136, 32, /* @__PURE__ */ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["oidNist"])(0x08));
const sha3_384 = /* @__PURE__ */ genKeccak(0x06, 104, 48, /* @__PURE__ */ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["oidNist"])(0x09));
const sha3_512 = /* @__PURE__ */ genKeccak(0x06, 72, 64, /* @__PURE__ */ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["oidNist"])(0x0a));
const keccak_224 = /* @__PURE__ */ genKeccak(0x01, 144, 28);
const keccak_256 = /* @__PURE__ */ genKeccak(0x01, 136, 32);
const keccak_384 = /* @__PURE__ */ genKeccak(0x01, 104, 48);
const keccak_512 = /* @__PURE__ */ genKeccak(0x01, 72, 64);
const genShake = (suffix, blockLen, outputLen, info = {})=>(0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["createHasher"])((opts = {})=>new Keccak(blockLen, suffix, opts.dkLen === undefined ? outputLen : opts.dkLen, true), info);
const shake128 = /* @__PURE__ */ genShake(0x1f, 168, 16, /* @__PURE__ */ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["oidNist"])(0x0b));
const shake256 = /* @__PURE__ */ genShake(0x1f, 136, 32, /* @__PURE__ */ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["oidNist"])(0x0c));
const shake128_32 = /* @__PURE__ */ genShake(0x1f, 168, 32, /* @__PURE__ */ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["oidNist"])(0x0b));
const shake256_64 = /* @__PURE__ */ genShake(0x1f, 136, 64, /* @__PURE__ */ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["oidNist"])(0x0c)); //# sourceMappingURL=sha3.js.map
}),
"[project]/node_modules/@noble/curves/abstract/fft.js [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "FFT",
    ()=>FFT,
    "FFTCore",
    ()=>FFTCore,
    "bitReversalInplace",
    ()=>bitReversalInplace,
    "bitReversalPermutation",
    ()=>bitReversalPermutation,
    "isPowerOfTwo",
    ()=>isPowerOfTwo,
    "log2",
    ()=>log2,
    "nextPowerOfTwo",
    ()=>nextPowerOfTwo,
    "poly",
    ()=>poly,
    "reverseBits",
    ()=>reverseBits,
    "rootsOfUnity",
    ()=>rootsOfUnity
]);
function checkU32(n) {
    // 0xff_ff_ff_ff
    if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new Error('wrong u32 integer:' + n);
    return n;
}
function isPowerOfTwo(x) {
    checkU32(x);
    return (x & x - 1) === 0 && x !== 0;
}
function nextPowerOfTwo(n) {
    checkU32(n);
    if (n <= 1) return 1;
    // FFT sizes here are used as JS array lengths, so `2^32` is not a meaningful result:
    // keep the fast u32 bit-twiddling path and fail explicitly instead of wrapping to 1.
    if (n > 0x8000_0000) throw new Error('nextPowerOfTwo overflow: result does not fit u32');
    return 1 << log2(n - 1) + 1 >>> 0;
}
function reverseBits(n, bits) {
    checkU32(n);
    if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32) throw new Error(`expected integer 0 <= bits <= 32, got ${bits}`);
    let reversed = 0;
    for(let i = 0; i < bits; i++, n >>>= 1)reversed = reversed << 1 | n & 1;
    // JS bitwise ops are signed i32; cast back so 32-bit reversals stay in the unsigned u32 domain.
    return reversed >>> 0;
}
function log2(n) {
    checkU32(n);
    return 31 - Math.clz32(n);
}
function bitReversalInplace(values) {
    const n = values.length;
    // Size-1 FFT is the identity, so bit-reversal must stay a no-op there instead of rejecting it.
    if (!isPowerOfTwo(n)) throw new Error('expected positive power-of-two length, got ' + n);
    const bits = log2(n);
    for(let i = 0; i < n; i++){
        const j = reverseBits(i, bits);
        if (i < j) {
            const tmp = values[i];
            values[i] = values[j];
            values[j] = tmp;
        }
    }
    return values;
}
function bitReversalPermutation(values) {
    return bitReversalInplace(values.slice());
}
const _1n = /** @__PURE__ */ BigInt(1);
function findGenerator(field) {
    let G = BigInt(2);
    for(; field.eql(field.pow(G, field.ORDER >> _1n), field.ONE); G++);
    return G;
}
function rootsOfUnity(field, generator) {
    // Factor field.ORDER-1 as oddFactor * 2^powerOfTwo
    let oddFactor = field.ORDER - _1n;
    let powerOfTwo = 0;
    for(; (oddFactor & _1n) !== _1n; powerOfTwo++, oddFactor >>= _1n);
    // Find non quadratic residue
    let G = generator !== undefined ? BigInt(generator) : findGenerator(field);
    // Powers of generator
    const omegas = new Array(powerOfTwo + 1);
    omegas[powerOfTwo] = field.pow(G, oddFactor);
    for(let i = powerOfTwo; i > 0; i--)omegas[i - 1] = field.sqr(omegas[i]);
    // Compute all roots of unity for powers up to maxPower
    const rootsCache = [];
    const checkBits = (bits)=>{
        checkU32(bits);
        if (bits > 31 || bits > powerOfTwo) throw new Error('rootsOfUnity: wrong bits ' + bits + ' powerOfTwo=' + powerOfTwo);
        return bits;
    };
    const precomputeRoots = (maxPower)=>{
        checkBits(maxPower);
        for(let power = maxPower; power >= 0; power--){
            if (rootsCache[power]) continue; // Skip if we've already computed roots for this power
            const rootsAtPower = [];
            for(let j = 0, cur = field.ONE; j < 2 ** power; j++, cur = field.mul(cur, omegas[power]))rootsAtPower.push(cur);
            rootsCache[power] = rootsAtPower;
        }
        return rootsCache[maxPower];
    };
    const brpCache = new Map();
    const inverseCache = new Map();
    // roots()/brp()/inverse() expose shared cached arrays by reference for speed; callers must treat them as read-only.
    // NOTE: we use bits instead of power, because power = 2**bits,
    // but power is not neccesary isPowerOfTwo(power)!
    return {
        info: {
            G,
            powerOfTwo,
            oddFactor
        },
        roots: (bits)=>{
            const b = checkBits(bits);
            return precomputeRoots(b);
        },
        brp (bits) {
            const b = checkBits(bits);
            if (brpCache.has(b)) return brpCache.get(b);
            else {
                const res = bitReversalPermutation(this.roots(b));
                brpCache.set(b, res);
                return res;
            }
        },
        inverse (bits) {
            const b = checkBits(bits);
            if (inverseCache.has(b)) return inverseCache.get(b);
            else {
                const res = field.invertBatch(this.roots(b));
                inverseCache.set(b, res);
                return res;
            }
        },
        omega: (bits)=>omegas[checkBits(bits)],
        clear: ()=>{
            rootsCache.splice(0, rootsCache.length);
            brpCache.clear();
            inverseCache.clear();
        }
    };
}
const FFTCore = (F, coreOpts)=>{
    const { N, roots, dit, invertButterflies = false, skipStages = 0, brp = true } = coreOpts;
    const bits = log2(N);
    if (!isPowerOfTwo(N)) throw new Error('FFT: Polynomial size should be power of two');
    // Wrong-sized root tables can stay in-bounds for some loop shapes and silently compute nonsense.
    if (roots.length !== N) throw new Error(`FFT: wrong roots length: expected ${N}, got ${roots.length}`);
    const isDit = dit !== invertButterflies;
    isDit;
    return (values)=>{
        if (values.length !== N) throw new Error('FFT: wrong Polynomial length');
        if (dit && brp) bitReversalInplace(values);
        for(let i = 0, g = 1; i < bits - skipStages; i++){
            // For each stage s (sub-FFT length m = 2^s)
            const s = dit ? i + 1 + skipStages : bits - i;
            const m = 1 << s;
            const m2 = m >> 1;
            const stride = N >> s;
            // Loop over each subarray of length m
            for(let k = 0; k < N; k += m){
                // Loop over each butterfly within the subarray
                for(let j = 0, grp = g++; j < m2; j++){
                    const rootPos = invertButterflies ? dit ? N - grp : grp : j * stride;
                    const i0 = k + j;
                    const i1 = k + j + m2;
                    const omega = roots[rootPos];
                    const b = values[i1];
                    const a = values[i0];
                    // Inlining gives us 10% perf in kyber vs functions
                    if (isDit) {
                        const t = F.mul(b, omega); // Standard DIT butterfly
                        values[i0] = F.add(a, t);
                        values[i1] = F.sub(a, t);
                    } else if (invertButterflies) {
                        values[i0] = F.add(b, a); // DIT loop + inverted butterflies (Kyber decode)
                        values[i1] = F.mul(F.sub(b, a), omega);
                    } else {
                        values[i0] = F.add(a, b); // Standard DIF butterfly
                        values[i1] = F.mul(F.sub(a, b), omega);
                    }
                }
            }
        }
        if (!dit && brp) bitReversalInplace(values);
        return values;
    };
};
function FFT(roots, opts) {
    const getLoop = (N, roots, brpInput = false, brpOutput = false)=>{
        if (brpInput && brpOutput) {
            // we cannot optimize this case, but lets support it anyway
            return (values)=>FFTCore(opts, {
                    N,
                    roots,
                    dit: false,
                    brp: false
                })(bitReversalInplace(values));
        }
        if (brpInput) return FFTCore(opts, {
            N,
            roots,
            dit: true,
            brp: false
        });
        if (brpOutput) return FFTCore(opts, {
            N,
            roots,
            dit: false,
            brp: false
        });
        return FFTCore(opts, {
            N,
            roots,
            dit: true,
            brp: true
        }); // all natural
    };
    return {
        direct (values, brpInput = false, brpOutput = false) {
            const N = values.length;
            if (!isPowerOfTwo(N)) throw new Error('FFT: Polynomial size should be power of two');
            const bits = log2(N);
            return getLoop(N, roots.roots(bits), brpInput, brpOutput)(values.slice());
        },
        inverse (values, brpInput = false, brpOutput = false) {
            const N = values.length;
            if (!isPowerOfTwo(N)) throw new Error('FFT: Polynomial size should be power of two');
            const bits = log2(N);
            const res = getLoop(N, roots.inverse(bits), brpInput, brpOutput)(values.slice());
            const ivm = opts.inv(BigInt(values.length)); // scale
            // we can get brp output if we use dif instead of dit!
            for(let i = 0; i < res.length; i++)res[i] = opts.mul(res[i], ivm);
            // Allows to re-use non-inverted roots, but is VERY fragile
            // return [res[0]].concat(res.slice(1).reverse());
            // inverse calculated as pow(-1), which transforms into ω^{-kn} (-> reverses indices)
            return res;
        }
    };
}
function poly(field, roots, create, fft, length) {
    const F = field;
    const _create = create || ((len, elm)=>new Array(len).fill(elm ?? F.ZERO));
    // `poly.mul(a, b)` distinguishes polynomial-vs-scalar at runtime, so keep accepted
    // polynomial containers concrete instead of trying to support arbitrary wrappers.
    const isPoly = (x)=>{
        if (Array.isArray(x)) return true;
        if (!ArrayBuffer.isView(x)) return false;
        const v = x;
        return typeof v.length === 'number' && typeof v.slice === 'function' && typeof v[Symbol.iterator] === 'function';
    };
    const checkLength = (...lst)=>{
        if (!lst.length) return 0;
        for (const i of lst)if (!isPoly(i)) throw new Error('poly: not polynomial: ' + i);
        const L = lst[0].length;
        for(let i = 1; i < lst.length; i++)if (lst[i].length !== L) throw new Error(`poly: mismatched lengths ${L} vs ${lst[i].length}`);
        if (length !== undefined && L !== length) throw new Error(`poly: expected fixed length ${length}, got ${L}`);
        return L;
    };
    function findOmegaIndex(x, n, brp = false) {
        const bits = log2(n);
        const omega = brp ? roots.brp(bits) : roots.roots(bits);
        for(let i = 0; i < n; i++)if (F.eql(x, omega[i])) return i;
        return -1;
    }
    // TODO: mutating versions for mlkem/mldsa
    return {
        roots,
        create: _create,
        length,
        extend: (a, len)=>{
            checkLength(a);
            const out = _create(len, F.ZERO);
            // Plain arrays grow when writing past `out.length`, so cap the copy explicitly to keep
            // `extend()` consistent with typed arrays and with its documented truncate behavior.
            for(let i = 0; i < Math.min(a.length, len); i++)out[i] = a[i];
            return out;
        },
        degree: (a)=>{
            checkLength(a);
            for(let i = a.length - 1; i >= 0; i--)if (!F.is0(a[i])) return i;
            return -1;
        },
        add: (a, b)=>{
            const len = checkLength(a, b);
            const out = _create(len);
            for(let i = 0; i < len; i++)out[i] = F.add(a[i], b[i]);
            return out;
        },
        sub: (a, b)=>{
            const len = checkLength(a, b);
            const out = _create(len);
            for(let i = 0; i < len; i++)out[i] = F.sub(a[i], b[i]);
            return out;
        },
        dot: (a, b)=>{
            const len = checkLength(a, b);
            const out = _create(len);
            for(let i = 0; i < len; i++)out[i] = F.mul(a[i], b[i]);
            return out;
        },
        mul: (a, b)=>{
            if (isPoly(b)) {
                const len = checkLength(a, b);
                if (fft) {
                    const A = fft.direct(a, false, true);
                    const B = fft.direct(b, false, true);
                    for(let i = 0; i < A.length; i++)A[i] = F.mul(A[i], B[i]);
                    return fft.inverse(A, true, false);
                } else {
                    // NOTE: this is quadratic and mostly for compat tests with FFT
                    const res = _create(len);
                    for(let i = 0; i < len; i++){
                        for(let j = 0; j < len; j++){
                            const k = (i + j) % len; // wrap mod length
                            res[k] = F.add(res[k], F.mul(a[i], b[j]));
                        }
                    }
                    return res;
                }
            } else {
                const out = _create(checkLength(a));
                for(let i = 0; i < out.length; i++)out[i] = F.mul(a[i], b);
                return out;
            }
        },
        convolve (a, b) {
            const len = nextPowerOfTwo(a.length + b.length - 1);
            return this.mul(this.extend(a, len), this.extend(b, len));
        },
        shift (p, factor) {
            const out = _create(checkLength(p));
            out[0] = p[0];
            for(let i = 1, power = F.ONE; i < p.length; i++){
                power = F.mul(power, factor);
                out[i] = F.mul(p[i], power);
            }
            return out;
        },
        clone: (a)=>{
            checkLength(a);
            const out = _create(a.length);
            for(let i = 0; i < a.length; i++)out[i] = a[i];
            return out;
        },
        eval: (a, basis)=>{
            checkLength(a, basis);
            let acc = F.ZERO;
            for(let i = 0; i < a.length; i++)acc = F.add(acc, F.mul(a[i], basis[i]));
            return acc;
        },
        monomial: {
            basis: (x, n)=>{
                const out = _create(n);
                let pow = F.ONE;
                for(let i = 0; i < n; i++){
                    out[i] = pow;
                    pow = F.mul(pow, x);
                }
                return out;
            },
            eval: (a, x)=>{
                checkLength(a);
                // Same as eval(a, monomialBasis(x, a.length)), but it is faster this way
                let acc = F.ZERO;
                for(let i = a.length - 1; i >= 0; i--)acc = F.add(F.mul(acc, x), a[i]);
                return acc;
            }
        },
        lagrange: {
            basis: (x, n, brp = false, weights)=>{
                const bits = log2(n);
                const cache = weights || (brp ? roots.brp(bits) : roots.roots(bits)); // [ω⁰, ω¹, ..., ωⁿ⁻¹]
                const out = _create(n);
                // Fast Kronecker-δ shortcut
                const idx = findOmegaIndex(x, n, brp);
                if (idx !== -1) {
                    out[idx] = F.ONE;
                    return out;
                }
                const tm = F.pow(x, BigInt(n));
                const c = F.mul(F.sub(tm, F.ONE), F.inv(BigInt(n))); // c = (xⁿ - 1)/n
                const denom = _create(n);
                for(let i = 0; i < n; i++)denom[i] = F.sub(x, cache[i]);
                const inv = F.invertBatch(denom);
                for(let i = 0; i < n; i++)out[i] = F.mul(c, F.mul(cache[i], inv[i]));
                return out;
            },
            eval (a, x, brp = false) {
                checkLength(a);
                const idx = findOmegaIndex(x, a.length, brp);
                if (idx !== -1) return a[idx]; // fast path
                const L = this.basis(x, a.length, brp); // Lᵢ(x)
                let acc = F.ZERO;
                for(let i = 0; i < a.length; i++)if (!F.is0(a[i])) acc = F.add(acc, F.mul(a[i], L[i]));
                return acc;
            }
        },
        vanishing (roots) {
            checkLength(roots);
            const out = _create(roots.length + 1, F.ZERO);
            out[0] = F.ONE;
            for (const r of roots){
                const neg = F.neg(r);
                for(let j = out.length - 1; j > 0; j--)out[j] = F.add(F.mul(out[j], neg), out[j - 1]);
                out[0] = F.mul(out[0], neg);
            }
            return out;
        }
    };
} //# sourceMappingURL=fft.js.map
}),
"[project]/node_modules/@noble/post-quantum/utils.js [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "EMPTY",
    ()=>EMPTY,
    "abytes",
    ()=>abytesDoc,
    "baswap64If",
    ()=>baswap64If,
    "byteSwap64",
    ()=>byteSwap64,
    "checkHash",
    ()=>checkHash,
    "cleanBytes",
    ()=>cleanBytes,
    "concatBytes",
    ()=>concatBytesDoc,
    "copyBytes",
    ()=>copyBytes,
    "equalBytes",
    ()=>equalBytes,
    "getMask",
    ()=>getMask,
    "getMessage",
    ()=>getMessage,
    "getMessagePrehash",
    ()=>getMessagePrehash,
    "randomBytes",
    ()=>randomBytes,
    "splitCoder",
    ()=>splitCoder,
    "validateOpts",
    ()=>validateOpts,
    "validateSigOpts",
    ()=>validateSigOpts,
    "validateVerOpts",
    ()=>validateVerOpts,
    "vecCoder",
    ()=>vecCoder
]);
/**
 * Utilities for hex, bytearray and number handling.
 * @module
 */ /*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/hashes/utils.js [app-ssr] (ecmascript)");
;
/**
 * Asserts that a value is a byte array and optionally checks its length.
 * Returns the original reference unchanged on success, and currently also accepts Node `Buffer`
 * values through the upstream validator.
 * This helper throws on malformed input, so APIs that must return `false` need to guard lengths
 * before decoding or before calling it.
 * @example
 * Validate that a value is a byte array with the expected length.
 * ```ts
 * abytes(new Uint8Array([1]), 1);
 * ```
 */ const abytesDoc = __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"];
;
/**
 * Concatenates byte arrays into a new `Uint8Array`.
 * Zero arguments return an empty `Uint8Array`.
 * Invalid segments throw before allocation because each argument is validated first.
 * @example
 * Concatenate two byte arrays into one result.
 * ```ts
 * concatBytes(new Uint8Array([1]), new Uint8Array([2]));
 * ```
 */ const concatBytesDoc = __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["concatBytes"];
;
const randomBytes = __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["randomBytes"];
function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for(let i = 0; i < a.length; i++)diff |= a[i] ^ b[i];
    return diff === 0;
}
function copyBytes(bytes) {
    // `Uint8Array.from(...)` would also accept arrays / other typed arrays. Keep this helper strict
    // because callers use it at byte-validation boundaries before mutating the detached copy.
    return Uint8Array.from((0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(bytes));
}
function byteSwap64(arr) {
    const bytes = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
    for(let i = 0; i < bytes.length; i += 8){
        const a0 = bytes[i + 0];
        const a1 = bytes[i + 1];
        const a2 = bytes[i + 2];
        const a3 = bytes[i + 3];
        bytes[i + 0] = bytes[i + 7];
        bytes[i + 1] = bytes[i + 6];
        bytes[i + 2] = bytes[i + 5];
        bytes[i + 3] = bytes[i + 4];
        bytes[i + 4] = a3;
        bytes[i + 5] = a2;
        bytes[i + 6] = a1;
        bytes[i + 7] = a0;
    }
    return arr;
}
const baswap64If = __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["isLE"] ? (arr)=>arr : byteSwap64;
function validateOpts(opts) {
    // Arrays silently passed here before, but these call sites expect named option-bag fields.
    if (Object.prototype.toString.call(opts) !== '[object Object]') throw new TypeError('expected valid options object');
}
function validateVerOpts(opts) {
    validateOpts(opts);
    if (opts.context !== undefined) (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(opts.context, undefined, 'opts.context');
}
function validateSigOpts(opts) {
    validateVerOpts(opts);
    if (opts.extraEntropy !== false && opts.extraEntropy !== undefined) (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(opts.extraEntropy, undefined, 'opts.extraEntropy');
}
function splitCoder(label, ...lengths) {
    const getLength = (c)=>typeof c === 'number' ? c : c.bytesLen;
    const bytesLen = lengths.reduce((sum, a)=>sum + getLength(a), 0);
    return {
        bytesLen,
        encode: (bufs)=>{
            const res = new Uint8Array(bytesLen);
            for(let i = 0, pos = 0; i < lengths.length; i++){
                const c = lengths[i];
                const l = getLength(c);
                const b = typeof c === 'number' ? bufs[i] : c.encode(bufs[i]);
                (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(b, l, label);
                res.set(b, pos);
                if (typeof c !== 'number') b.fill(0); // clean
                pos += l;
            }
            return res;
        },
        decode: (buf)=>{
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(buf, bytesLen, label);
            const res = [];
            for (const c of lengths){
                const l = getLength(c);
                const b = buf.subarray(0, l);
                res.push(typeof c === 'number' ? b : c.decode(b));
                buf = buf.subarray(l);
            }
            return res;
        }
    };
}
function vecCoder(c, vecLen) {
    const coder = c;
    const bytesLen = vecLen * coder.bytesLen;
    return {
        bytesLen,
        encode: (u)=>{
            if (u.length !== vecLen) throw new RangeError(`vecCoder.encode: wrong length=${u.length}. Expected: ${vecLen}`);
            const res = new Uint8Array(bytesLen);
            for(let i = 0, pos = 0; i < u.length; i++){
                const b = coder.encode(u[i]);
                res.set(b, pos);
                b.fill(0); // clean
                pos += b.length;
            }
            return res;
        },
        decode: (a)=>{
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(a, bytesLen);
            const r = [];
            for(let i = 0; i < a.length; i += coder.bytesLen)r.push(coder.decode(a.subarray(i, i + coder.bytesLen)));
            return r;
        }
    };
}
function cleanBytes(...list) {
    for (const t of list){
        if (Array.isArray(t)) for (const b of t)b.fill(0);
        else t.fill(0);
    }
}
function getMask(bits) {
    if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32) throw new RangeError(`expected bits in [0..32], got ${bits}`);
    // JS shifts are modulo 32, so bit 32 needs an explicit full-width mask.
    return bits === 32 ? 0xffffffff : ~(-1 << bits) >>> 0;
}
const EMPTY = /* @__PURE__ */ Uint8Array.of();
function getMessage(msg, ctx = EMPTY) {
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(msg);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(ctx);
    if (ctx.length > 255) throw new RangeError('context should be 255 bytes or less');
    return (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["concatBytes"])(new Uint8Array([
        0,
        ctx.length
    ]), ctx, msg);
}
// DER tag+length plus the shared NIST hash OID arc 2.16.840.1.101.3.4.2.* used by the
// FIPS 204 / FIPS 205 pre-hash wrappers; the final byte selects SHA-256, SHA-512, SHAKE128,
// SHAKE256, or another approved hash/XOF under that subtree.
// 06 09 60 86 48 01 65 03 04 02
const oidNistP = /* @__PURE__ */ Uint8Array.from([
    6,
    9,
    0x60,
    0x86,
    0x48,
    1,
    0x65,
    3,
    4,
    2
]);
function checkHash(hash, requiredStrength = 0) {
    if (!hash.oid || !equalBytes(hash.oid.subarray(0, 10), oidNistP)) throw new Error('hash.oid is invalid: expected NIST hash');
    // FIPS 204 / FIPS 205 require both collision and second-preimage strength; for approved NIST
    // hashes/XOFs under this OID subtree, the collision bound from the configured digest length is
    // the tighter runtime check, so enforce that lower bound here.
    const collisionResistance = hash.outputLen * 8 / 2;
    if (requiredStrength > collisionResistance) {
        throw new Error('Pre-hash security strength too low: ' + collisionResistance + ', required: ' + requiredStrength);
    }
}
function getMessagePrehash(hash, msg, ctx = EMPTY) {
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(msg);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(ctx);
    if (ctx.length > 255) throw new RangeError('context should be 255 bytes or less');
    const hashed = hash(msg);
    return (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["concatBytes"])(new Uint8Array([
        1,
        ctx.length
    ]), ctx, hash.oid, hashed);
} //# sourceMappingURL=utils.js.map
}),
"[project]/node_modules/@noble/post-quantum/_crystals.js [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "XOF128",
    ()=>XOF128,
    "XOF256",
    ()=>XOF256,
    "genCrystals",
    ()=>genCrystals
]);
/**
 * Internal methods for lattice-based ML-KEM and ML-DSA.
 * @module
 */ /*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$curves$2f$abstract$2f$fft$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/curves/abstract/fft.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$sha3$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/hashes/sha3.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/post-quantum/utils.js [app-ssr] (ecmascript)");
;
;
;
const genCrystals = (opts)=>{
    // isKyber: true means Kyber, false means Dilithium
    const { newPoly, N, Q, F, ROOT_OF_UNITY, brvBits, isKyber } = opts;
    // Normalize JS `%` into the canonical Z_m representative `[0, modulo-1]` expected by
    // FIPS 203 §2.3 / FIPS 204 §2.3 before downstream mod-q arithmetic.
    const mod = (a, modulo = Q)=>{
        const result = a % modulo | 0;
        return (result >= 0 ? result | 0 : modulo + result | 0) | 0;
    };
    // FIPS 204 §7.4 uses the centered `mod ±` representative for low bits, keeping the
    // positive midpoint when `modulo` is even.
    // Center to `[-floor((modulo-1)/2), floor(modulo/2)]`.
    const smod = (a, modulo = Q)=>{
        const r = mod(a, modulo) | 0;
        return (r > modulo >> 1 ? r - modulo | 0 : r) | 0;
    };
    // Kyber uses the FIPS 203 Appendix A `BitRev_7` table here via the first 128 entries, while
    // Dilithium uses the FIPS 204 §7.5 / Appendix B `BitRev_8` zetas table over all 256 entries.
    function getZettas() {
        const out = newPoly(N);
        for(let i = 0; i < N; i++){
            const b = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$curves$2f$abstract$2f$fft$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["reverseBits"])(i, brvBits);
            const p = BigInt(ROOT_OF_UNITY) ** BigInt(b) % BigInt(Q);
            out[i] = Number(p) | 0;
        }
        return out;
    }
    const nttZetas = getZettas();
    // Number-Theoretic Transform
    // Explained: https://electricdusk.com/ntt.html
    // Kyber has slightly different params, since there is no 512th primitive root of unity mod q,
    // only 256th primitive root of unity mod. Which also complicates MultiplyNTT.
    const field = {
        add: (a, b)=>mod((a | 0) + (b | 0)) | 0,
        sub: (a, b)=>mod((a | 0) - (b | 0)) | 0,
        mul: (a, b)=>mod((a | 0) * (b | 0)) | 0,
        inv: (_a)=>{
            throw new Error('not implemented');
        }
    };
    const nttOpts = {
        N,
        roots: nttZetas,
        invertButterflies: true,
        skipStages: isKyber ? 1 : 0,
        brp: false
    };
    const dif = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$curves$2f$abstract$2f$fft$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["FFTCore"])(field, {
        dit: false,
        ...nttOpts
    });
    const dit = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$curves$2f$abstract$2f$fft$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["FFTCore"])(field, {
        dit: true,
        ...nttOpts
    });
    const NTT = {
        encode: (r)=>{
            return dif(r);
        },
        decode: (r)=>{
            dit(r);
            // The inverse-NTT normalization factor is family-specific: FIPS 203 Algorithm 10 line 14
            // uses `128^-1 mod q` for Kyber, while FIPS 204 Algorithm 42 lines 21-23 use `256^-1 mod q`.
            // kyber uses 128 here, because brv && stuff
            for(let i = 0; i < r.length; i++)r[i] = mod(F * r[i]);
            return r;
        }
    };
    // Pack one little-endian `d`-bit word per coefficient, matching FIPS 203 ByteEncode /
    // ByteDecode and the FIPS 204 BitsToBytes-based polynomial packing helpers.
    const bitsCoder = (d, c)=>{
        const mask = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["getMask"])(d);
        const bytesLen = d * (N / 8);
        return {
            bytesLen,
            encode: (poly_)=>{
                const poly = poly_;
                const r = new Uint8Array(bytesLen);
                for(let i = 0, buf = 0, bufLen = 0, pos = 0; i < poly.length; i++){
                    buf |= (c.encode(poly[i]) & mask) << bufLen;
                    bufLen += d;
                    for(; bufLen >= 8; bufLen -= 8, buf >>= 8)r[pos++] = buf & (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["getMask"])(bufLen);
                }
                return r;
            },
            decode: (bytes)=>{
                const r = newPoly(N);
                for(let i = 0, buf = 0, bufLen = 0, pos = 0; i < bytes.length; i++){
                    buf |= bytes[i] << bufLen;
                    bufLen += 8;
                    for(; bufLen >= d; bufLen -= d, buf >>= d)r[pos++] = c.decode(buf & mask);
                }
                return r;
            }
        };
    };
    return {
        mod,
        smod,
        nttZetas: nttZetas,
        NTT: {
            encode: (r)=>NTT.encode(r),
            decode: (r)=>NTT.decode(r)
        },
        bitsCoder: bitsCoder
    };
};
const createXofShake = (shake)=>(seed, blockLen)=>{
        if (!blockLen) blockLen = shake.blockLen;
        // Optimizations that won't mater:
        // - cached seed update (two .update(), on start and on the end)
        // - another cache which cloned into working copy
        // Faster than multiple updates, since seed less than blockLen
        const _seed = new Uint8Array(seed.length + 2);
        _seed.set(seed);
        const seedLen = seed.length;
        const buf = new Uint8Array(blockLen); // == shake128.blockLen
        let h = shake.create({});
        let calls = 0;
        let xofs = 0;
        return {
            stats: ()=>({
                    calls,
                    xofs
                }),
            get: (x, y)=>{
                // Rebind to `seed || x || y` so callers can implement the spec's per-coordinate
                // SHAKE inputs like `rho || j || i` and `rho || IntegerToBytes(counter, 2)`.
                _seed[seedLen + 0] = x;
                _seed[seedLen + 1] = y;
                h.destroy();
                h = shake.create({}).update(_seed);
                calls++;
                return ()=>{
                    xofs++;
                    return h.xofInto(buf);
                };
            },
            clean: ()=>{
                h.destroy();
                (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["cleanBytes"])(buf, _seed);
            }
        };
    };
const XOF128 = /* @__PURE__ */ createXofShake(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$sha3$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["shake128"]);
const XOF256 = /* @__PURE__ */ createXofShake(__TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$sha3$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["shake256"]); //# sourceMappingURL=_crystals.js.map
}),
"[project]/node_modules/@noble/post-quantum/ml-kem.js [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "PARAMS",
    ()=>PARAMS,
    "__tests",
    ()=>__tests,
    "ml_kem1024",
    ()=>ml_kem1024,
    "ml_kem512",
    ()=>ml_kem512,
    "ml_kem768",
    ()=>ml_kem768
]);
/**
 * ML-KEM: Module Lattice-based Key Encapsulation Mechanism from
 * [FIPS-203](https://csrc.nist.gov/pubs/fips/203/ipd). A.k.a. CRYSTALS-Kyber.
 *
 * Key encapsulation is similar to DH / ECDH (think X25519), with important differences:
 * * Unlike in ECDH, we can't verify if it was "Bob" who've sent the shared secret
 * * Unlike ECDH, it is probabalistic and relies on quality of randomness (CSPRNG).
 * * Decapsulation never throws an error, even when shared secret was
 *   encrypted by a different public key. It will just return a different shared secret.
 *
 * There are some concerns with regards to security: see
 * [djb blog](https://blog.cr.yp.to/20231003-countcorrectly.html) and
 * [mailing list](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/W2VOzy0wz_E).
 *
 * Has similar internals to ML-DSA, but their keys and params are different.
 *
 * Check out [official site](https://www.pq-crystals.org/kyber/resources.shtml),
 * [repo](https://github.com/pq-crystals/kyber),
 * [spec](https://datatracker.ietf.org/doc/draft-cfrg-schwabe-kyber/).
 * @module
 */ /*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */ var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$sha3$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/hashes/sha3.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/hashes/utils.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$_crystals$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/post-quantum/_crystals.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/@noble/post-quantum/utils.js [app-ssr] (ecmascript)");
;
;
;
;
/** Key encapsulation mechanism interface */ const N = 256; // Kyber (not FIPS-203) supports different lengths, but all std modes were using 256
const Q = 3329; // 13*(2**8)+1, modulo prime
const F = 3303; // 3303 ≡ 128**(−1) mod q (FIPS-203)
const ROOT_OF_UNITY = 17; // ζ = 17 ∈ Zq is a primitive 256-th root of unity modulo Q. ζ**128 ≡−1
// treeshake: keep genCrystals behind the object so PARAMS-only bundles can drop it entirely.
// Shared CRYSTALS helper in the ML-KEM branch: Kyber mode, 7-bit bit-reversal,
// and Uint16Array polys because current coefficients stay reduced modulo q.
const crystals = /* @__PURE__ */ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$_crystals$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["genCrystals"])({
    N,
    Q,
    F,
    ROOT_OF_UNITY,
    newPoly: (n)=>new Uint16Array(n),
    brvBits: 7,
    isKyber: true
});
const PARAMS = /* @__PURE__ */ (()=>Object.freeze({
        512: Object.freeze({
            N,
            Q,
            K: 2,
            ETA1: 3,
            ETA2: 2,
            du: 10,
            dv: 4,
            RBGstrength: 128
        }),
        768: Object.freeze({
            N,
            Q,
            K: 3,
            ETA1: 2,
            ETA2: 2,
            du: 10,
            dv: 4,
            RBGstrength: 192
        }),
        1024: Object.freeze({
            N,
            Q,
            K: 4,
            ETA1: 2,
            ETA2: 2,
            du: 11,
            dv: 5,
            RBGstrength: 256
        })
    }))();
// FIPS-203: compress/decompress
const compress = (d)=>{
    // d=12 is the ByteEncode12/ByteDecode12 path, not lossy compression.
    // ByteDecode12 interprets each 12-bit word modulo q; without that reduction the public-key
    // modulus check in encapsulate() becomes a no-op for malformed coefficients like 4095.
    if (d >= 12) return {
        encode: (i)=>i,
        decode: (i)=>i >= Q ? i - Q : i
    };
    // Comments map to python implementation in RFC (draft-cfrg-schwabe-kyber)
    // const round = (i: number) => Math.floor(i + 0.5) | 0;
    const a = 2 ** (d - 1);
    return {
        // This only matches standalone Compress_d after bitsCoder masks the result into Z_(2^d).
        encode: (i)=>((i << d) + Q / 2) / Q,
        // const decompress = (i: number) => round((Q / 2 ** d) * i);
        decode: (i)=>i * Q + a >>> d
    };
};
// Raw ByteEncode_d / ByteDecode_d from FIPS 203 operate on d-bit words directly.
// That differs from `polyCoder(d)` for d<12, where noble folds packing together with the lossy
// ciphertext compression step used by u/v. Tests that exercise the spec's raw packing surface need
// this exact non-lossy variant instead.
const byteCoder = (d)=>crystals.bitsCoder(d, d === 12 ? {
        encode: (i)=>i,
        decode: (i)=>i >= Q ? i - Q : i
    } : {
        encode: (i)=>i,
        decode: (i)=>i
    });
// NOTE: we merge encoding and compress because it is faster, also both require same d param
// d=12 is the ByteEncode12/ByteDecode12 path rather than compression, and caller-side
// public-key modulus checks route through this helper's decode/encode roundtrip.
// Converts between bytes and d-bits compressed representation.
// Kinda like convertRadix2 from @scure/base.
// decode(encode(t)) == t, but there is loss of information on encode(decode(t))
const polyCoder = (d)=>d === 12 ? byteCoder(12) : crystals.bitsCoder(d, compress(d));
function polyAdd(a_, b_) {
    const a = a_;
    const b = b_;
    // Mutates `a` in place; callers must pass two N=256 polynomials.
    for(let i = 0; i < N; i++)a[i] = crystals.mod(a[i] + b[i]); // a += b
}
function polySub(a_, b_) {
    const a = a_;
    const b = b_;
    // Mutates `a` in place; callers must pass two N=256 polynomials.
    for(let i = 0; i < N; i++)a[i] = crystals.mod(a[i] - b[i]); // a -= b
}
// FIPS-203: Computes the product of two degree-one polynomials with respect to a quadratic modulus
function BaseCaseMultiply(a0, a1, b0, b1, zeta) {
    // `zeta` here is Algorithm 11's γ = ζ^(2BitRev_7(i)+1).
    const c0 = crystals.mod(a1 * b1 * zeta + a0 * b0);
    const c1 = crystals.mod(a0 * b1 + a1 * b0);
    return {
        c0,
        c1
    };
}
// FIPS-203: Computes the product (in the ring Tq) of two NTT representations.
// Works in place on `f`; `g` is read-only and both inputs must already be in NTT form.
function MultiplyNTTs(f_, g_) {
    const f = f_;
    const g = g_;
    for(let i = 0; i < N / 2; i++){
        let z = crystals.nttZetas[64 + (i >> 1)];
        if (i & 1) z = -z;
        const { c0, c1 } = BaseCaseMultiply(f[2 * i + 0], f[2 * i + 1], g[2 * i + 0], g[2 * i + 1], z);
        f[2 * i + 0] = c0;
        f[2 * i + 1] = c1;
    }
    return f;
}
// Return poly in NTT representation
function SampleNTT(xof_) {
    const xof = xof_;
    // The reader must already bind the Algorithm 7 seed||j||i bytes
    // and return block lengths divisible by 3.
    const r = new Uint16Array(N);
    for(let j = 0; j < N;){
        const b = xof();
        if (b.length % 3) throw new Error('SampleNTT: unaligned block');
        for(let i = 0; j < N && i + 3 <= b.length; i += 3){
            const d1 = (b[i + 0] >> 0 | b[i + 1] << 8) & 0xfff;
            const d2 = (b[i + 1] >> 4 | b[i + 2] << 4) & 0xfff;
            if (d1 < Q) r[j++] = d1;
            if (j < N && d2 < Q) r[j++] = d2;
        }
    }
    return r;
}
// Sampling from the centered binomial distribution
// Returns poly with small coefficients (noise/errors) stored modulo q in ordinary coefficient form.
// Current callers only use Table 2 eta values {2,3} and PRF outputs of exactly 64*eta bytes.
const sampleCBDBytes = (buf, eta)=>{
    const r = new Uint16Array(N);
    // CBD consumes the PRF bitstream in little-endian byte order; normalize the word view on BE,
    // then swap it back so callers still observe `buf` as read-only.
    const b32 = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["u32"])(buf);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["swap32IfBE"])(b32);
    let len = 0;
    for(let i = 0, p = 0, bb = 0, t0 = 0; i < b32.length; i++){
        let b = b32[i];
        for(let j = 0; j < 32; j++){
            bb += b & 1;
            b >>= 1;
            len += 1;
            if (len === eta) {
                t0 = bb;
                bb = 0;
            } else if (len === 2 * eta) {
                r[p++] = crystals.mod(t0 - bb);
                bb = 0;
                len = 0;
            }
        }
    }
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["swap32IfBE"])(b32);
    if (len) throw new Error(`sampleCBD: leftover bits: ${len}`);
    return r;
};
function sampleCBD(PRF_, seed, nonce, eta) {
    const PRF = PRF_;
    return sampleCBDBytes(PRF(eta * N / 4, seed, nonce), eta);
}
// K-PKE
// Internal ML-KEM subroutine only: exact 32-byte `seed` / `msg` inputs
// come from Algorithms 13-15, and the helper mutates decoded temporary
// polynomials in place while leaving caller byte arrays unchanged.
const genKPKE = (opts_)=>{
    const opts = opts_;
    const { K, PRF, XOF, HASH512, ETA1, ETA2, du, dv } = opts;
    const poly1 = polyCoder(1);
    const polyV = polyCoder(dv);
    const polyU = polyCoder(du);
    const publicCoder = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["splitCoder"])('publicKey', (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["vecCoder"])(polyCoder(12), K), 32);
    const secretCoder = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["vecCoder"])(polyCoder(12), K);
    const cipherCoder = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["splitCoder"])('ciphertext', (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["vecCoder"])(polyU, K), polyV);
    const seedCoder = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["splitCoder"])('seed', 32, 32);
    return {
        secretCoder,
        lengths: {
            secretKey: secretCoder.bytesLen,
            publicKey: publicCoder.bytesLen,
            cipherText: cipherCoder.bytesLen
        },
        keygen: (seed)=>{
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(seed, 32, 'seed');
            const seedDst = new Uint8Array(33);
            seedDst.set(seed);
            // FIPS 203 Algorithm 13 appends the parameter-set byte `k`
            // before `G(d || k)`, so expanding the same 32-byte seed
            // under a different ML-KEM parameter set yields unrelated keys.
            seedDst[32] = K;
            const seedHash = HASH512(seedDst);
            const [rho, sigma] = seedCoder.decode(seedHash);
            const sHat = [];
            const tHat = [];
            for(let i = 0; i < K; i++)sHat.push(crystals.NTT.encode(sampleCBD(PRF, sigma, i, ETA1)));
            const x = XOF(rho);
            for(let i = 0; i < K; i++){
                const e = crystals.NTT.encode(sampleCBD(PRF, sigma, K + i, ETA1));
                for(let j = 0; j < K; j++){
                    const aji = SampleNTT(x.get(j, i)); // A[i][j], inplace
                    polyAdd(e, MultiplyNTTs(aji, sHat[j]));
                }
                tHat.push(e); // t ← A ◦ s + e
            }
            x.clean();
            const res = {
                publicKey: publicCoder.encode([
                    tHat,
                    rho
                ]),
                secretKey: secretCoder.encode(sHat)
            };
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["cleanBytes"])(rho, sigma, sHat, tHat, seedDst, seedHash);
            return res;
        },
        encrypt: (publicKey, msg, seed)=>{
            const [tHat, rho] = publicCoder.decode(publicKey);
            const rHat = [];
            for(let i = 0; i < K; i++)rHat.push(crystals.NTT.encode(sampleCBD(PRF, seed, i, ETA1)));
            const x = XOF(rho);
            const tmp2 = new Uint16Array(N);
            const u = [];
            for(let i = 0; i < K; i++){
                const e1 = sampleCBD(PRF, seed, K + i, ETA2);
                const tmp = new Uint16Array(N);
                for(let j = 0; j < K; j++){
                    const aij = SampleNTT(x.get(i, j)); // A[j][i], inplace transpose access
                    polyAdd(tmp, MultiplyNTTs(aij, rHat[j])); // t += aij * rHat[j]
                }
                polyAdd(e1, crystals.NTT.decode(tmp)); // e1 += tmp
                u.push(e1);
                polyAdd(tmp2, MultiplyNTTs(tHat[i], rHat[i])); // t2 += tHat[i] * rHat[i]
                (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["cleanBytes"])(tmp);
            }
            x.clean();
            const e2 = sampleCBD(PRF, seed, 2 * K, ETA2);
            polyAdd(e2, crystals.NTT.decode(tmp2)); // e2 += tmp2
            const v = poly1.decode(msg); // encode plaintext m into polynomial v
            polyAdd(v, e2); // v += e2
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["cleanBytes"])(tHat, rHat, tmp2, e2);
            return cipherCoder.encode([
                u,
                v
            ]);
        },
        decrypt: (cipherText, privateKey)=>{
            const [u, v] = cipherCoder.decode(cipherText);
            const sk = secretCoder.decode(privateKey); // s  ← ByteDecode_12(dkPKE)
            const tmp = new Uint16Array(N);
            // tmp += sk[i] * u[i]
            for(let i = 0; i < K; i++)polyAdd(tmp, MultiplyNTTs(sk[i], crystals.NTT.encode(u[i])));
            polySub(v, crystals.NTT.decode(tmp)); // w = v' - tmp
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["cleanBytes"])(tmp, sk, u);
            return poly1.encode(v);
        }
    };
};
/**
 * Public ML-KEM wrapper over the internal K-PKE subroutine.
 * `keygen(seed)` and `encapsulate(publicKey, msg)` are deterministic/test-oriented hooks that map
 * more directly to Algorithms 16-17 than to the pure no-input / random-internal Algorithms 19-20.
 * decapsulate() tries to follow the Algorithms 18/21 implicit-reject structure as closely as
 * practical here by re-encrypting, comparing ciphertexts, returning `Khat` on match or `Kbar` on
 * mismatch, and zeroizing the non-returned shared-secret candidate; JS/JIT still provides no
 * constant-time guarantees for that path.
 */ function createKyber(opts) {
    const rawOpts = opts;
    const KPKE = genKPKE(rawOpts);
    const { HASH256, HASH512, KDF } = rawOpts;
    const { secretCoder: KPKESecretCoder, lengths } = KPKE;
    const secretCoder = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["splitCoder"])('secretKey', lengths.secretKey, lengths.publicKey, 32, 32);
    const msgLen = 32;
    const seedLen = 64;
    const kemLengths = Object.freeze({
        ...lengths,
        seed: 64,
        msg: msgLen,
        msgRand: msgLen,
        secretKey: secretCoder.bytesLen
    });
    return Object.freeze({
        info: Object.freeze({
            type: 'ml-kem'
        }),
        lengths: kemLengths,
        keygen: (seed = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["randomBytes"])(seedLen))=>{
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(seed, seedLen, 'seed');
            const { publicKey, secretKey: sk } = KPKE.keygen(seed.subarray(0, 32));
            const publicKeyHash = HASH256(publicKey);
            // (dkPKE||ek||H(ek)||z)
            const secretKey = secretCoder.encode([
                sk,
                publicKey,
                publicKeyHash,
                seed.subarray(32)
            ]);
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["cleanBytes"])(sk, publicKeyHash);
            return {
                publicKey: publicKey,
                secretKey: secretKey
            };
        },
        getPublicKey: (secretKey)=>{
            const [_sk, publicKey, _publicKeyHash, _z] = secretCoder.decode(secretKey);
            return Uint8Array.from(publicKey);
        },
        encapsulate: (publicKey, msg = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["randomBytes"])(msgLen))=>{
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(publicKey, lengths.publicKey, 'publicKey');
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(msg, msgLen, 'message');
            // FIPS-203 includes additional verification check for modulus
            const eke = publicKey.subarray(0, 384 * opts.K);
            // Copy because of inplace encoding
            const ek = KPKESecretCoder.encode(KPKESecretCoder.decode((0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["copyBytes"])(eke)));
            // (Modulus check.) Perform the computation ek ← ByteEncode12(ByteDecode12(eke)).
            // If ek = ̸ eke, the input is invalid. (See Section 4.2.1.)
            if (!(0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["equalBytes"])(ek, eke)) {
                (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["cleanBytes"])(ek);
                throw new Error('ML-KEM.encapsulate: wrong publicKey modulus');
            }
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["cleanBytes"])(ek);
            // derive randomness
            const kr = HASH512.create().update(msg).update(HASH256(publicKey)).digest();
            const cipherText = KPKE.encrypt(publicKey, msg, kr.subarray(32, 64));
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["cleanBytes"])(kr.subarray(32));
            return {
                cipherText: cipherText,
                sharedSecret: kr.subarray(0, 32)
            };
        },
        decapsulate: (cipherText, secretKey)=>{
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(secretKey, secretCoder.bytesLen, 'secretKey'); // 768*k + 96
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(cipherText, lengths.cipherText, 'cipherText'); // 32(du*k + dv)
            // test ← H(dk[384𝑘 ∶ 768𝑘 + 32])) .
            const k768 = secretCoder.bytesLen - 96;
            const start = k768 + 32;
            const test = HASH256(secretKey.subarray(k768 / 2, start));
            // If test ≠ dk[768𝑘 + 32 ∶ 768𝑘 + 64], then input checking has failed.
            if (!(0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["equalBytes"])(test, secretKey.subarray(start, start + 32))) throw new Error('invalid secretKey: hash check failed');
            const [sk, publicKey, publicKeyHash, z] = secretCoder.decode(secretKey);
            const msg = KPKE.decrypt(cipherText, sk);
            // derive randomness, Khat, rHat = G(mHat || h)
            const kr = HASH512.create().update(msg).update(publicKeyHash).digest();
            const Khat = kr.subarray(0, 32);
            // re-encrypt using the derived randomness
            const cipherText2 = KPKE.encrypt(publicKey, msg, kr.subarray(32, 64));
            // if ciphertexts do not match, “implicitly reject”
            const isValid = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["equalBytes"])(cipherText, cipherText2);
            const Kbar = KDF.create({
                dkLen: 32
            }).update(z).update(cipherText).digest();
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["cleanBytes"])(msg, cipherText2, !isValid ? Khat : Kbar);
            return isValid ? Khat : Kbar;
        }
    });
}
// FIPS 203's PRF_eta binding: current callers use only 32-byte keys, one-byte nonces,
// and dkLen values {128, 192}; out-of-range nonce numbers still wrap modulo 256 here.
function shakePRF(dkLen, key, nonce) {
    return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$sha3$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["shake256"].create({
        dkLen
    }).update(key).update(new Uint8Array([
        nonce
    ])).digest();
}
// Fixed ML-KEM hash/XOF bindings. `KDF` here is the spec's fixed 32-byte `J` call,
// and swapping any field changes the scheme rather than tuning an internal dependency.
const opts = /* @__PURE__ */ (()=>({
        HASH256: __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$sha3$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["sha3_256"],
        HASH512: __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$sha3$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["sha3_512"],
        KDF: __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$hashes$2f$sha3$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["shake256"],
        XOF: __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$_crystals$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["XOF128"],
        PRF: shakePRF
    }))();
// Parameter-set instantiation step for the spec's "ML-KEM-x" names; current correctness relies
// on the internal PARAMS rows rather than local validation of arbitrary KEMParam objects.
const mk = (params)=>createKyber({
        ...opts,
        ...params
    });
const ml_kem512 = /* @__PURE__ */ (()=>mk(PARAMS[512]))();
const ml_kem768 = /* @__PURE__ */ (()=>mk(PARAMS[768]))();
const ml_kem1024 = /* @__PURE__ */ (()=>mk(PARAMS[1024]))();
const __tests = /* @__PURE__ */ (()=>Object.freeze({
        Compress_d: (x, d)=>{
            if (d < 1 || d > 11) throw new Error(`Compress_d: expected d in [1..11], got ${d}`);
            return compress(d).encode(x) & (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["getMask"])(d);
        },
        Decompress_d: (y, d)=>{
            if (d < 1 || d > 11) throw new Error(`Decompress_d: expected d in [1..11], got ${d}`);
            return compress(d).decode(y);
        },
        ByteEncode_d: (F, d)=>{
            if (d < 1 || d > 12) throw new Error(`ByteEncode_d: expected d in [1..12], got ${d}`);
            return byteCoder(d).encode(F);
        },
        ByteDecode_d: (B, d)=>{
            if (d < 1 || d > 12) throw new Error(`ByteDecode_d: expected d in [1..12], got ${d}`);
            return byteCoder(d).decode(B);
        },
        NTT: (f)=>crystals.NTT.encode(Uint16Array.from(f)),
        NTT_inv: (fHat)=>crystals.NTT.decode(Uint16Array.from(fHat)),
        MultiplyNTTs: (fHat, gHat)=>MultiplyNTTs(Uint16Array.from(fHat), Uint16Array.from(gHat)),
        SamplePolyCBD: (B, eta)=>{
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(B, 64 * eta, 'B');
            return sampleCBDBytes(B, eta);
        },
        SampleNTT: (B)=>{
            (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$utils$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["abytes"])(B, 34, 'B');
            const xof = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$noble$2f$post$2d$quantum$2f$_crystals$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["XOF128"])(B.subarray(0, 32));
            try {
                return SampleNTT(xof.get(B[32], B[33]));
            } finally{
                xof.clean();
            }
        }
    }))(); //# sourceMappingURL=ml-kem.js.map
}),
];

//# sourceMappingURL=_98d3193d._.js.map