export const ASYMMETRIC_ALGO = {
  RSA_OAEP: "rsa_oaep",
  HYBRID_RSA_AES: "hybrid_rsa_aes",
  RSA_PSS: "rsa_pss",
  ECDH: "ecdh",
};

export function asymmetricInfo(algo) {
  switch (algo) {
    case ASYMMETRIC_ALGO.RSA_OAEP:
      return "RSA-OAEP (WebCrypto): mã hóa/giải mã chuỗi UTF-8. Output là Base64. Cần tạo keypair trước.";
    case ASYMMETRIC_ALGO.HYBRID_RSA_AES:
      return "Session key encryption (demo): AES-GCM mã dữ liệu + RSA-OAEP mã session key. Output là JSON.";
    case ASYMMETRIC_ALGO.RSA_PSS:
      return "Digital Signature (demo): RSA-PSS ký (Sign) tạo chữ ký Base64, Verify dùng chữ ký trong ô Kết quả.";
    case ASYMMETRIC_ALGO.ECDH:
      return "Diffie–Hellman kiểu (ECDH P-256): demo tạo shared secret giữa Alice/Bob (Base64).";
    default:
      return "";
  }
}

export function ensureWebCrypto() {
  if (!window.crypto?.subtle) {
    return { ok: false, error: "Trình duyệt không hỗ trợ WebCrypto (crypto.subtle)." };
  }
  return { ok: true };
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return window.btoa(binary);
}

function base64ToBytes(base64) {
  const binary = window.atob((base64 || "").trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function abToBase64(ab) {
  return bytesToBase64(new Uint8Array(ab));
}

function base64ToAb(base64) {
  return base64ToBytes(base64).buffer;
}

function pemWrap(label, base64) {
  const clean = base64.replace(/\s+/g, "");
  const lines = clean.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

export async function generateRsaOaepKeyPair() {
  const wc = ensureWebCrypto();
  if (!wc.ok) return { ok: false, error: wc.error };

  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
    const spki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicPem = pemWrap("PUBLIC KEY", abToBase64(spki));
    return { ok: true, value: { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, publicPem } };
  } catch {
    return { ok: false, error: "Không thể tạo RSA keypair." };
  }
}

export async function generateRsaPssKeyPair() {
  const wc = ensureWebCrypto();
  if (!wc.ok) return { ok: false, error: wc.error };

  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );
    const spki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicPem = pemWrap("PUBLIC KEY", abToBase64(spki));
    return { ok: true, value: { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, publicPem } };
  } catch {
    return { ok: false, error: "Không thể tạo RSA-PSS keypair." };
  }
}

export async function rsaOaepEncryptDecrypt({ mode, text, keyPair }) {
  const wc = ensureWebCrypto();
  if (!wc.ok) return { ok: false, error: wc.error };
  if (!keyPair?.publicKey || !keyPair?.privateKey) return { ok: false, error: "Vui lòng tạo RSA keypair trước." };

  try {
    if (mode === "encrypt") {
      const data = new TextEncoder().encode(text || "");
      const ct = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, keyPair.publicKey, data);
      return { ok: true, value: abToBase64(ct) };
    }
    const ct = base64ToAb(text || "");
    const pt = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, keyPair.privateKey, ct);
    return { ok: true, value: new TextDecoder().decode(pt) };
  } catch {
    return { ok: false, error: "RSA encrypt/decrypt thất bại (dữ liệu không đúng hoặc key không khớp)." };
  }
}

export async function hybridEncryptDecrypt({ mode, text, keyPair }) {
  const wc = ensureWebCrypto();
  if (!wc.ok) return { ok: false, error: wc.error };
  if (!keyPair?.publicKey || !keyPair?.privateKey) {
    return { ok: false, error: "Vui lòng tạo RSA-OAEP keypair trước (dùng để mã session key)." };
  }

  try {
    if (mode === "encrypt") {
      const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const data = new TextEncoder().encode(text || "");
      const ct = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, data);
      const wrappedKey = await window.crypto.subtle.wrapKey("raw", aesKey, keyPair.publicKey, { name: "RSA-OAEP" });
      const payload = {
        alg: "AES-GCM+RSA-OAEP",
        iv: bytesToBase64(iv),
        key: abToBase64(wrappedKey),
        ct: abToBase64(ct),
      };
      return { ok: true, value: JSON.stringify(payload, null, 2) };
    }

    const payload = JSON.parse(text || "");
    const iv = base64ToBytes(payload.iv);
    const wrappedKey = base64ToAb(payload.key);
    const ct = base64ToAb(payload.ct);
    const aesKey = await window.crypto.subtle.unwrapKey(
      "raw",
      wrappedKey,
      keyPair.privateKey,
      { name: "RSA-OAEP" },
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    const pt = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
    return { ok: true, value: new TextDecoder().decode(pt) };
  } catch {
    return { ok: false, error: "Hybrid decrypt thất bại (payload không đúng hoặc key không khớp)." };
  }
}

export async function rsaPssSignVerify({ mode, text, signatureBase64, keyPair }) {
  const wc = ensureWebCrypto();
  if (!wc.ok) return { ok: false, error: wc.error };
  if (!keyPair?.publicKey || !keyPair?.privateKey) return { ok: false, error: "Vui lòng tạo RSA-PSS keypair trước." };

  try {
    const data = new TextEncoder().encode(text || "");
    if (mode === "sign") {
      const sig = await window.crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, keyPair.privateKey, data);
      return { ok: true, value: abToBase64(sig) };
    }

    const sig = base64ToAb(signatureBase64 || "");
    if (!sig.byteLength) return { ok: false, error: "Vui lòng có chữ ký để Verify." };
    const ok = await window.crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, keyPair.publicKey, sig, data);
    return { ok: true, value: ok ? "Verify: HỢP LỆ" : "Verify: KHÔNG HỢP LỆ" };
  } catch {
    return { ok: false, error: "Sign/Verify thất bại." };
  }
}

export async function ecdhDemo() {
  const wc = ensureWebCrypto();
  if (!wc.ok) return { ok: false, error: wc.error };

  try {
    const alice = await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const bob = await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const alicePub = await window.crypto.subtle.exportKey("raw", alice.publicKey);
    const bobPub = await window.crypto.subtle.exportKey("raw", bob.publicKey);
    const aliceSecret = await window.crypto.subtle.deriveBits({ name: "ECDH", public: bob.publicKey }, alice.privateKey, 256);
    const bobSecret = await window.crypto.subtle.deriveBits({ name: "ECDH", public: alice.publicKey }, bob.privateKey, 256);
    const a = abToBase64(aliceSecret);
    const b = abToBase64(bobSecret);
    const match = a === b;
    const value = `ECDH (P-256)\n\nAlice public (raw, Base64):\n${abToBase64(
      alicePub
    )}\n\nBob public (raw, Base64):\n${abToBase64(bobPub)}\n\nShared secret (Alice):\n${a}\n\nShared secret (Bob):\n${b}\n\nMatch: ${match ? "YES" : "NO"}`;
    return { ok: true, value };
  } catch {
    return { ok: false, error: "ECDH demo thất bại." };
  }
}

