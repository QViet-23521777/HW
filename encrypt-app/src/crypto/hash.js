import CryptoJS from "crypto-js";

export const HMAC_ALGO = {
  SHA1: "HMAC-SHA-1",
  SHA224: "HMAC-SHA-224",
  SHA256: "HMAC-SHA-256",
  SHA384: "HMAC-SHA-384",
  SHA512: "HMAC-SHA-512",
};

export function getHashes(text) {
  const msg = text || "";
  if (!msg) return [];
  return [
    { name: "MD5", value: CryptoJS.MD5(msg).toString() },
    { name: "SHA-1", value: CryptoJS.SHA1(msg).toString() },
    { name: "SHA-2-224", value: CryptoJS.SHA224(msg).toString() },
    { name: "SHA-2-256", value: CryptoJS.SHA256(msg).toString() },
    { name: "SHA-2-384", value: CryptoJS.SHA384(msg).toString() },
    { name: "SHA-2-512", value: CryptoJS.SHA512(msg).toString() },
    { name: "SHA-3-256", value: CryptoJS.SHA3(msg, { outputLength: 256 }).toString() },
    { name: "SHA-3-512", value: CryptoJS.SHA3(msg, { outputLength: 512 }).toString() },
  ];
}

export function computeHmac({ algo, text, key }) {
  const msg = text || "";
  const k = (key || "").trim();
  if (!msg || !k) return { ok: false, error: "Vui lòng nhập văn bản và secret key cho MAC." };

  if (algo === HMAC_ALGO.SHA1) return { ok: true, value: CryptoJS.HmacSHA1(msg, k).toString() };
  if (algo === HMAC_ALGO.SHA224) return { ok: true, value: CryptoJS.HmacSHA224(msg, k).toString() };
  if (algo === HMAC_ALGO.SHA256) return { ok: true, value: CryptoJS.HmacSHA256(msg, k).toString() };
  if (algo === HMAC_ALGO.SHA384) return { ok: true, value: CryptoJS.HmacSHA384(msg, k).toString() };
  if (algo === HMAC_ALGO.SHA512) return { ok: true, value: CryptoJS.HmacSHA512(msg, k).toString() };
  return { ok: false, error: "HMAC algorithm chưa được hỗ trợ." };
}

