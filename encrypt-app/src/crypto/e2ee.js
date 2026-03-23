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

const E2EE_INFO = new TextEncoder().encode("encrypt-app:e2ee-demo:v1");

export function e2eeInfo() {
  return [
    "E2EE (End‑to‑End Encryption) demo: mỗi tin nhắn dùng ECDH (P‑256) + HKDF‑SHA‑256 để sinh khóa AES‑256‑GCM.",
    "Payload là JSON (server chỉ thấy ciphertext + thông tin công khai). Chỉ người nhận có private key mới giải mã được.",
  ].join(" ");
}

export async function generateIdentityKeyPair() {
  const wc = ensureWebCrypto();
  if (!wc.ok) return { ok: false, error: wc.error };

  try {
    const keyPair = await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const publicRaw = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
    return {
      ok: true,
      value: {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        publicKeyBase64: abToBase64(publicRaw),
      },
    };
  } catch {
    return { ok: false, error: "Không thể tạo ECDH identity keypair." };
  }
}

async function importPublicKeyFromBase64(publicKeyBase64) {
  const wc = ensureWebCrypto();
  if (!wc.ok) throw new Error(wc.error);
  const raw = base64ToAb(publicKeyBase64 || "");
  return window.crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, []);
}

async function deriveAesKeyFromEcdhBits({ ecdhBits, saltBytes }) {
  const wc = ensureWebCrypto();
  if (!wc.ok) throw new Error(wc.error);
  const keyMaterial = await window.crypto.subtle.importKey("raw", ecdhBits, "HKDF", false, ["deriveKey"]);
  return window.crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: E2EE_INFO },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function aadForPayload(payload) {
  // Bind metadata + ephemeral key into AEAD so tampering is detected.
  const text = `e2ee-demo:v1|from=${payload.from || ""}|to=${payload.to || ""}|eph=${payload.ephPub || ""}`;
  return new TextEncoder().encode(text);
}

export async function e2eeEncrypt({ plaintext, from, to, recipientPublicKeyBase64 }) {
  const wc = ensureWebCrypto();
  if (!wc.ok) return { ok: false, error: wc.error };
  if (!recipientPublicKeyBase64) return { ok: false, error: "Thiếu public key của người nhận." };

  try {
    const recipientPublicKey = await importPublicKeyFromBase64(recipientPublicKeyBase64);
    const eph = await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const ephPubRaw = await window.crypto.subtle.exportKey("raw", eph.publicKey);

    const ecdhBits = await window.crypto.subtle.deriveBits({ name: "ECDH", public: recipientPublicKey }, eph.privateKey, 256);
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await deriveAesKeyFromEcdhBits({ ecdhBits, saltBytes: salt });

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(plaintext || "");

    const payload = {
      v: 1,
      alg: "ECDH-ES+HKDF-SHA-256+AES-256-GCM",
      from: from || "",
      to: to || "",
      ephPub: abToBase64(ephPubRaw),
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ct: "",
    };

    const ct = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aadForPayload(payload) }, aesKey, data);
    payload.ct = abToBase64(ct);

    return { ok: true, value: JSON.stringify(payload, null, 2) };
  } catch {
    return { ok: false, error: "E2EE encrypt thất bại." };
  }
}

export async function e2eeDecrypt({ payloadJson, recipientPrivateKey }) {
  const wc = ensureWebCrypto();
  if (!wc.ok) return { ok: false, error: wc.error };
  if (!recipientPrivateKey) return { ok: false, error: "Thiếu private key của người nhận (chưa tạo keypair?)." };

  try {
    const payload = JSON.parse(payloadJson || "");
    if (payload?.v !== 1) return { ok: false, error: "Payload không hợp lệ (version)." };
    if (!payload?.ephPub || !payload?.salt || !payload?.iv || !payload?.ct) return { ok: false, error: "Payload thiếu trường bắt buộc." };

    const ephPublicKey = await importPublicKeyFromBase64(payload.ephPub);
    const ecdhBits = await window.crypto.subtle.deriveBits({ name: "ECDH", public: ephPublicKey }, recipientPrivateKey, 256);

    const salt = base64ToBytes(payload.salt);
    const aesKey = await deriveAesKeyFromEcdhBits({ ecdhBits, saltBytes: salt });

    const iv = base64ToBytes(payload.iv);
    const ct = base64ToAb(payload.ct);

    const pt = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aadForPayload(payload) },
      aesKey,
      ct
    );
    return { ok: true, value: new TextDecoder().decode(pt) };
  } catch {
    return { ok: false, error: "E2EE decrypt thất bại (payload sai hoặc key không khớp)." };
  }
}

