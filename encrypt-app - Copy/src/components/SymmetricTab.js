import React, { useMemo, useState } from "react";
import { runSymmetric, SYMMETRIC_ALGO, symmetricInfo } from "../crypto/symmetric";

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

  const info = useMemo(() => symmetricInfo(algo), [algo]);

  const clear = () => {
    setPlainText("");
    setResult("");
    setError("");
    setCopyMessage("");
  };

  const run = (mode) => {
    setCopyMessage("");
    const res = runSymmetric({ algo, mode, input: plainText, secretKey });
    if (!res.ok) {
      setResult("");
      setError(res.error || "Thao tác thất bại.");
      return;
    }
    setResult(res.value || "");
    setError("");
  };

  return (
    <section className="tabContent active">
      <div className="algoInfo">{info}</div>

      <div className="field">
        <label htmlFor="symmetricAlgo">Giải thuật</label>
        <select
          id="symmetricAlgo"
          value={algo}
          onChange={(e) => setAlgo(e.target.value)}
        >
          <option value={SYMMETRIC_ALGO.AES}>AES / Rijndael (CryptoJS)</option>
        </select>
      </div>

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
        <button
          type="button"
          className="btn success"
          onClick={() => run("encrypt")}
        >
          Mã hóa
        </button>
        <button
          type="button"
          className="btn primary"
          onClick={() => run("decrypt")}
        >
          Giải mã
        </button>
        <button type="button" className="btn danger" onClick={clear}>
          Xóa
        </button>
      </div>
    </section>
  );
}
