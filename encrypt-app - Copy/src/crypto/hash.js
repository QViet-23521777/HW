import CryptoJS from "crypto-js";

export const HMAC_ALGO = {
  SHA256: "HMAC-SHA-256",
  SHA512: "HMAC-SHA-512",
};

export function getHashes(text) {
  const msg = text || "";
  if (!msg) return [];
  return [
    { name: "SHA-256", value: CryptoJS.SHA256(msg).toString() },
    { name: "SHA-512", value: CryptoJS.SHA512(msg).toString() },
  ];
}

export function computeHmac({ algo, text, key }) {
  const msg = text || "";
  const k = (key || "").trim();
  if (!msg || !k)
    return { ok: false, error: "Vui lòng nhập văn bản và secret key cho MAC." };

  if (algo === HMAC_ALGO.SHA256)
    return { ok: true, value: CryptoJS.HmacSHA256(msg, k).toString() };
  if (algo === HMAC_ALGO.SHA512)
    return { ok: true, value: CryptoJS.HmacSHA512(msg, k).toString() };
  return { ok: false, error: "HMAC algorithm chưa được hỗ trợ." };
}
