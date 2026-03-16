import React, { useMemo, useState } from "react";
import { generateOtpKeyForText, runSymmetric, SYMMETRIC_ALGO, symmetricInfo } from "../crypto/symmetric";

function copyToClipboard(setCopyMessage, text) {
  if (!text) return;
  navigator.clipboard
    .writeText(text)
    .then(() => {
      setCopyMessage("Đã copy kết quả vào clipboard.");
      window.setTimeout(() => setCopyMessage(""), 2000);
    })
    .catch(() => {
      setCopyMessage("Không thể copy (trình duyệt chặn clipboard).");
      window.setTimeout(() => setCopyMessage(""), 2500);
    });
}

export default function SymmetricTab() {
  const [algo, setAlgo] = useState(SYMMETRIC_ALGO.AES);
  const [secretKey, setSecretKey] = useState("");
  const [plainText, setPlainText] = useState("");

  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [copyMessage, setCopyMessage] = useState("");

  const [caesarShiftValue, setCaesarShiftValue] = useState("3");
  const [substitutionMap, setSubstitutionMap] = useState("QWERTYUIOPASDFGHJKLZXCVBNM");
  const [transpositionKey, setTranspositionKey] = useState("SECRET");
  const [vigenereKey, setVigenereKey] = useState("KEY");

  const info = useMemo(() => symmetricInfo(algo), [algo]);

  const clear = () => {
    setPlainText("");
    setResult("");
    setError("");
    setCopyMessage("");
  };

  const run = (mode) => {
    setCopyMessage("");
    const res = runSymmetric({
      algo,
      mode,
      input: plainText,
      secretKey,
      caesarShiftValue,
      substitutionMap,
      transpositionKey,
      vigenereKey,
    });
    if (!res.ok) {
      setResult("");
      setError(res.error || "Thao tác thất bại.");
      return;
    }
    setResult(res.value || "");
    setError("");
  };

  const generateOtp = () => {
    const k = generateOtpKeyForText(plainText);
    if (!k) {
      setError("Không có ký tự A–Z để tạo OTP key.");
      return;
    }
    setVigenereKey(k);
    setError("");
  };

  return (
    <section className="tabContent active">
      <div className="algoInfo">{info}</div>

      <div className="field">
        <label htmlFor="symmetricAlgo">Giải thuật</label>
        <select id="symmetricAlgo" value={algo} onChange={(e) => setAlgo(e.target.value)}>
          <optgroup label="Khối (block cipher)">
            <option value={SYMMETRIC_ALGO.AES}>AES / Rijndael (CryptoJS)</option>
            <option value={SYMMETRIC_ALGO.DES}>DES (CryptoJS)</option>
          </optgroup>
          <optgroup label="Cổ điển (classical)">
            <option value={SYMMETRIC_ALGO.CAESAR}>Caesar Cipher</option>
            <option value={SYMMETRIC_ALGO.SUBSTITUTION}>Substitution Cipher</option>
            <option value={SYMMETRIC_ALGO.TRANSPOSITION}>Transposition (columnar)</option>
            <option value={SYMMETRIC_ALGO.VIGENERE}>One-Time Pad / Vigenère (text)</option>
          </optgroup>
          <optgroup label="Dòng (stream)">
            <option value={SYMMETRIC_ALGO.STREAM_XOR}>Stream Cipher (XOR keystream)</option>
          </optgroup>
        </select>
      </div>

      {(algo === SYMMETRIC_ALGO.AES || algo === SYMMETRIC_ALGO.DES || algo === SYMMETRIC_ALGO.STREAM_XOR) && (
        <div className="field">
          <label htmlFor="secretKey">Secret key</label>
          <input
            id="secretKey"
            type="text"
            value={secretKey}
            onChange={(e) => setSecretKey(e.target.value)}
            placeholder="Nhập secret key"
            autoComplete="off"
            spellCheck="false"
          />
        </div>
      )}

      {algo === SYMMETRIC_ALGO.CAESAR && (
        <div className="field">
          <label htmlFor="caesarShift">Shift</label>
          <input
            id="caesarShift"
            type="number"
            value={caesarShiftValue}
            onChange={(e) => setCaesarShiftValue(e.target.value)}
            placeholder="3"
          />
        </div>
      )}

      {algo === SYMMETRIC_ALGO.SUBSTITUTION && (
        <div className="field">
          <label htmlFor="subMap">Bảng thay thế (26 ký tự A–Z)</label>
          <input
            id="subMap"
            type="text"
            value={substitutionMap}
            onChange={(e) => setSubstitutionMap(e.target.value)}
            placeholder="Ví dụ: QWERTYUIOPASDFGHJKLZXCVBNM"
            autoComplete="off"
            spellCheck="false"
          />
        </div>
      )}

      {algo === SYMMETRIC_ALGO.TRANSPOSITION && (
        <div className="field">
          <label htmlFor="transKey">Keyword (khóa hoán vị)</label>
          <input
            id="transKey"
            type="text"
            value={transpositionKey}
            onChange={(e) => setTranspositionKey(e.target.value)}
            placeholder="Ví dụ: SECRET"
            autoComplete="off"
            spellCheck="false"
          />
        </div>
      )}

      {algo === SYMMETRIC_ALGO.VIGENERE && (
        <div className="field">
          <label htmlFor="vigKey">Key (A–Z)</label>
          <div className="keyRow">
            <input
              id="vigKey"
              type="text"
              value={vigenereKey}
              onChange={(e) => setVigenereKey(e.target.value)}
              placeholder="Ví dụ: KEY"
              autoComplete="off"
              spellCheck="false"
            />
            <button type="button" className="btn secondary" onClick={generateOtp}>
              Tạo OTP key
            </button>
          </div>
        </div>
      )}

      <div className="grid">
        <div className="field">
          <div className="fieldHeader">
            <label htmlFor="symInput">Văn bản đầu vào</label>
            <span className="hint">Plain text hoặc cipher text</span>
          </div>
          <textarea
            id="symInput"
            rows="7"
            value={plainText}
            onChange={(e) => setPlainText(e.target.value)}
            placeholder="Nhập nội dung cần mã hóa hoặc cần giải mã…"
          />
        </div>

        <div className="field">
          <div className="fieldHeader">
            <label htmlFor="symOut">Kết quả</label>
            <button
              type="button"
              className="linkButton"
              onClick={() => copyToClipboard(setCopyMessage, result)}
              disabled={!result}
              aria-disabled={!result}
            >
              Copy
            </button>
          </div>
          <textarea id="symOut" rows="7" value={result} readOnly />
          {copyMessage ? <div className="toast">{copyMessage}</div> : null}
          {error ? <div className="error">{error}</div> : null}
        </div>
      </div>

      <div className="buttons">
        <button type="button" className="btn success" onClick={() => run("encrypt")}>
          Mã hóa
        </button>
        <button type="button" className="btn primary" onClick={() => run("decrypt")}>
          Giải mã
        </button>
        <button type="button" className="btn danger" onClick={clear}>
          Xóa
        </button>
      </div>
    </section>
  );
}

