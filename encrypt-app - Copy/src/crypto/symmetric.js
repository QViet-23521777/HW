import CryptoJS from "crypto-js";

export const SYMMETRIC_ALGO = {
  AES: "aes",
};

function normalizeKey(key) {
  return (key || "").trim();
}

export function symmetricInfo(algo) {
  switch (algo) {
    case SYMMETRIC_ALGO.AES:
      return "AES (CryptoJS): dùng passphrase (string) để mã hóa/giải mã. Ciphertext là chuỗi Base64 (OpenSSL format).";
    default:
      return "";
  }
}

export function runSymmetric({ algo, mode, input, secretKey }) {
  const text = input || "";

  if (algo === SYMMETRIC_ALGO.AES) {
    const k = normalizeKey(secretKey);
    if (!text || !k)
      return { ok: false, error: "Vui lòng nhập văn bản và secret key." };
    if (mode === "encrypt")
      return { ok: true, value: CryptoJS.AES.encrypt(text, k).toString() };
    try {
      const bytes = CryptoJS.AES.decrypt(text, k);
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);
      if (!decrypted)
        return {
          ok: false,
          error: "Giải mã thất bại (key hoặc dữ liệu không đúng).",
        };
      return { ok: true, value: decrypted };
    } catch {
      return {
        ok: false,
        error: "Giải mã thất bại (key hoặc dữ liệu không đúng).",
      };
    }
  }

  return { ok: false, error: "Thuật toán chưa được hỗ trợ." };
}
