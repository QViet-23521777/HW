import CryptoJS from "crypto-js";

export const SYMMETRIC_ALGO = {
  AES: "aes",
  DES: "des",
  CAESAR: "caesar",
  SUBSTITUTION: "substitution",
  TRANSPOSITION: "transposition",
  VIGENERE: "vigenere",
  STREAM_XOR: "stream_xor",
};

function normalizeKey(key) {
  return (key || "").trim();
}

function clampInt(value, min, max, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function caesarShift(text, shift) {
  const s = ((shift % 26) + 26) % 26;
  return Array.from(text)
    .map((ch) => {
      const code = ch.charCodeAt(0);
      if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + s) % 26) + 65);
      if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + s) % 26) + 97);
      return ch;
    })
    .join("");
}

function parseSubstitutionMap(raw) {
  const map = (raw || "").toUpperCase().replace(/[^A-Z]/g, "");
  if (map.length !== 26) return { ok: false, error: "Bảng thay thế phải có đúng 26 ký tự (A–Z)." };
  const set = new Set(map.split(""));
  if (set.size !== 26) return { ok: false, error: "Bảng thay thế không được trùng ký tự." };
  return { ok: true, map };
}

function substitution(text, map, mode) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const forward = new Map(alpha.split("").map((ch, i) => [ch, map[i]]));
  const reverse = new Map(map.split("").map((ch, i) => [ch, alpha[i]]));

  return Array.from(text)
    .map((ch) => {
      const upper = ch.toUpperCase();
      const table = mode === "decrypt" ? reverse : forward;
      if (!table.has(upper)) return ch;
      const mapped = table.get(upper);
      return ch === upper ? mapped : mapped.toLowerCase();
    })
    .join("");
}

function getColumnOrder(keyword) {
  const key = String(keyword || "");
  const items = Array.from(key).map((ch, idx) => ({ ch: ch.toUpperCase(), idx }));
  items.sort((a, b) => (a.ch < b.ch ? -1 : a.ch > b.ch ? 1 : a.idx - b.idx));
  return items.map((x) => x.idx);
}

function columnarTranspositionEncrypt(text, keyword) {
  const key = String(keyword || "");
  if (!key) return { ok: false, error: "Vui lòng nhập khóa hoán vị (keyword)." };

  const cols = key.length;
  const order = getColumnOrder(key);
  const rows = Math.ceil(text.length / cols);
  const total = rows * cols;
  const padChar = "X";
  const padded = text.padEnd(total, padChar);

  let out = "";
  for (const col of order) {
    for (let r = 0; r < rows; r++) out += padded[r * cols + col];
  }
  return { ok: true, value: out };
}

function columnarTranspositionDecrypt(cipher, keyword) {
  const key = String(keyword || "");
  if (!key) return { ok: false, error: "Vui lòng nhập khóa hoán vị (keyword)." };
  if (!cipher) return { ok: true, value: "" };

  const cols = key.length;
  const order = getColumnOrder(key);
  const rows = Math.ceil(cipher.length / cols);
  const total = rows * cols;
  const padChar = "X";
  const padded = cipher.padEnd(total, padChar);

  const columns = new Array(cols).fill("");
  let offset = 0;
  for (const col of order) {
    columns[col] = padded.slice(offset, offset + rows);
    offset += rows;
  }

  let out = "";
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) out += columns[c][r] || "";
  }
  return { ok: true, value: out };
}

function alphaIndex(ch) {
  const code = ch.charCodeAt(0);
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 97;
  return -1;
}

function vigenere(text, key, mode) {
  const k = (key || "").toUpperCase().replace(/[^A-Z]/g, "");
  if (!k) return { ok: false, error: "Vui lòng nhập key (chỉ A–Z) cho Vigenère/OTP." };

  let ki = 0;
  const out = Array.from(text).map((ch) => {
    const idx = alphaIndex(ch);
    if (idx < 0) return ch;
    const shift = k.charCodeAt(ki % k.length) - 65;
    ki += 1;
    const next = mode === "decrypt" ? (idx - shift + 26) % 26 : (idx + shift) % 26;
    const isUpper = ch === ch.toUpperCase();
    const base = isUpper ? 65 : 97;
    return String.fromCharCode(base + next);
  });
  return { ok: true, value: out.join("") };
}

function makeKeystream(key, nBytes) {
  const out = CryptoJS.lib.WordArray.create();
  let counter = 0;
  while (out.sigBytes < nBytes) {
    const block = CryptoJS.SHA256(`${key}:${counter}`);
    out.concat(block);
    counter += 1;
  }
  out.sigBytes = nBytes;
  out.clamp();
  return out;
}

function xorWordArrays(a, b) {
  const nWords = Math.ceil(a.sigBytes / 4);
  const words = new Array(nWords);
  for (let i = 0; i < nWords; i++) words[i] = (a.words[i] ^ b.words[i]) | 0;
  return CryptoJS.lib.WordArray.create(words, a.sigBytes);
}

function streamXorEncrypt(plain, key) {
  if (!plain || !key) return { ok: false, error: "Vui lòng nhập văn bản và key." };
  const p = CryptoJS.enc.Utf8.parse(plain);
  const ks = makeKeystream(key, p.sigBytes);
  const c = xorWordArrays(p, ks);
  return { ok: true, value: CryptoJS.enc.Base64.stringify(c) };
}

function streamXorDecrypt(cipherBase64, key) {
  if (!cipherBase64 || !key) return { ok: false, error: "Vui lòng nhập cipher text (Base64) và key." };
  try {
    const c = CryptoJS.enc.Base64.parse(cipherBase64.trim());
    const ks = makeKeystream(key, c.sigBytes);
    const p = xorWordArrays(c, ks);
    return { ok: true, value: CryptoJS.enc.Utf8.stringify(p) };
  } catch {
    return { ok: false, error: "Cipher text không hợp lệ (cần Base64)." };
  }
}

export function symmetricInfo(algo) {
  switch (algo) {
    case SYMMETRIC_ALGO.AES:
      return "AES (CryptoJS): dùng passphrase (string) để mã hóa/giải mã. Ciphertext là chuỗi Base64 (OpenSSL format).";
    case SYMMETRIC_ALGO.DES:
      return "DES (CryptoJS): chỉ dùng cho mục đích học tập; DES không còn an toàn trong thực tế.";
    case SYMMETRIC_ALGO.CAESAR:
      return "Caesar Cipher: dịch chuyển chữ cái theo số bước (mặc định 3).";
    case SYMMETRIC_ALGO.SUBSTITUTION:
      return "Substitution Cipher: thay thế từng chữ cái theo bảng ánh xạ 26 ký tự.";
    case SYMMETRIC_ALGO.TRANSPOSITION:
      return "Transposition Cipher (columnar): sắp xếp lại theo thứ tự cột dựa trên keyword.";
    case SYMMETRIC_ALGO.VIGENERE:
      return "Vigenère / OTP (text): cộng modulo 26 theo key (chỉ A–Z). OTP đúng nghĩa cần key ngẫu nhiên dài bằng plaintext.";
    case SYMMETRIC_ALGO.STREAM_XOR:
      return "Stream cipher (demo): tạo keystream từ SHA-256(key:counter), XOR với dữ liệu. Ciphertext là Base64.";
    default:
      return "";
  }
}

export function generateOtpKeyForText(text) {
  const letters = Array.from(text || "").filter((ch) => alphaIndex(ch) >= 0).length;
  if (!letters) return "";
  const bytes = new Uint8Array(letters);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => String.fromCharCode(65 + (b % 26)))
    .join("");
}

export function runSymmetric({ algo, mode, input, secretKey, caesarShiftValue, substitutionMap, transpositionKey, vigenereKey }) {
  const text = input || "";

  if (algo === SYMMETRIC_ALGO.AES) {
    const k = normalizeKey(secretKey);
    if (!text || !k) return { ok: false, error: "Vui lòng nhập văn bản và secret key." };
    if (mode === "encrypt") return { ok: true, value: CryptoJS.AES.encrypt(text, k).toString() };
    try {
      const bytes = CryptoJS.AES.decrypt(text, k);
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);
      if (!decrypted) return { ok: false, error: "Giải mã thất bại (key hoặc dữ liệu không đúng)." };
      return { ok: true, value: decrypted };
    } catch {
      return { ok: false, error: "Giải mã thất bại (key hoặc dữ liệu không đúng)." };
    }
  }

  if (algo === SYMMETRIC_ALGO.DES) {
    const k = normalizeKey(secretKey);
    if (!text || !k) return { ok: false, error: "Vui lòng nhập văn bản và secret key." };
    if (mode === "encrypt") return { ok: true, value: CryptoJS.DES.encrypt(text, k).toString() };
    try {
      const bytes = CryptoJS.DES.decrypt(text, k);
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);
      if (!decrypted) return { ok: false, error: "Giải mã thất bại (key hoặc dữ liệu không đúng)." };
      return { ok: true, value: decrypted };
    } catch {
      return { ok: false, error: "Giải mã thất bại (key hoặc dữ liệu không đúng)." };
    }
  }

  if (algo === SYMMETRIC_ALGO.CAESAR) {
    const shift = clampInt(caesarShiftValue, -10000, 10000, 3);
    return { ok: true, value: caesarShift(text, mode === "decrypt" ? -shift : shift) };
  }

  if (algo === SYMMETRIC_ALGO.SUBSTITUTION) {
    const parsed = parseSubstitutionMap(substitutionMap);
    if (!parsed.ok) return { ok: false, error: parsed.error };
    return { ok: true, value: substitution(text, parsed.map, mode) };
  }

  if (algo === SYMMETRIC_ALGO.TRANSPOSITION) {
    const k = normalizeKey(transpositionKey);
    const res = mode === "encrypt" ? columnarTranspositionEncrypt(text, k) : columnarTranspositionDecrypt(text, k);
    if (!res.ok) return { ok: false, error: res.error };
    return { ok: true, value: res.value };
  }

  if (algo === SYMMETRIC_ALGO.VIGENERE) {
    const k = normalizeKey(vigenereKey);
    const res = vigenere(text, k, mode);
    if (!res.ok) return { ok: false, error: res.error };
    return { ok: true, value: res.value };
  }

  if (algo === SYMMETRIC_ALGO.STREAM_XOR) {
    const k = normalizeKey(secretKey);
    const res = mode === "encrypt" ? streamXorEncrypt(text, k) : streamXorDecrypt(text, k);
    if (!res.ok) return { ok: false, error: res.error };
    return { ok: true, value: res.value };
  }

  return { ok: false, error: "Thuật toán chưa được hỗ trợ." };
}

