import React, { useMemo, useState } from "react";
import { computeHmac, getHashes, HMAC_ALGO } from "../crypto/hash";

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

export default function HashTab() {
  const [text, setText] = useState("");

  const [hmacAlgo, setHmacAlgo] = useState(HMAC_ALGO.SHA256);
  const [hmacKey, setHmacKey] = useState("");
  const [hmacResult, setHmacResult] = useState("");
  const [error, setError] = useState("");
  const [copyMessage, setCopyMessage] = useState("");

  const hashes = useMemo(() => getHashes(text), [text]);

  const clear = () => {
    setText("");
    setHmacResult("");
    setError("");
    setCopyMessage("");
  };

  const runHmac = () => {
    setCopyMessage("");
    const res = computeHmac({ algo: hmacAlgo, text, key: hmacKey });
    if (!res.ok) {
      setHmacResult("");
      setError(res.error || "Thao tác thất bại.");
      return;
    }
    setHmacResult(res.value || "");
    setError("");
  };

  return (
    <section className="tabContent active">
      <div className="algoInfo">Hash: không đảo ngược. MAC (HMAC) dùng secret key để xác thực toàn vẹn dữ liệu.</div>

      <div className="grid">
        <div className="field">
          <div className="fieldHeader">
            <label htmlFor="hashInput">Văn bản</label>
            <span className="hint">Dùng chung cho Hash và HMAC</span>
          </div>
          <textarea
            id="hashInput"
            rows="7"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Nhập dữ liệu để băm/MAC…"
          />
        </div>

        <div className="field">
          <div className="fieldHeader">
            <label>HMAC</label>
            <span className="hint">Tùy chọn</span>
          </div>

          <label htmlFor="hmacAlgo" className="hint">
            Thuật toán
          </label>
          <select id="hmacAlgo" value={hmacAlgo} onChange={(e) => setHmacAlgo(e.target.value)}>
            <option value={HMAC_ALGO.SHA1}>HMAC-SHA-1</option>
            <option value={HMAC_ALGO.SHA224}>HMAC-SHA-224</option>
            <option value={HMAC_ALGO.SHA256}>HMAC-SHA-256</option>
            <option value={HMAC_ALGO.SHA384}>HMAC-SHA-384</option>
            <option value={HMAC_ALGO.SHA512}>HMAC-SHA-512</option>
          </select>

          <label htmlFor="hmacKey" className="hint">
            Secret key
          </label>
          <input
            id="hmacKey"
            type="text"
            value={hmacKey}
            onChange={(e) => setHmacKey(e.target.value)}
            placeholder="Nhập key cho HMAC…"
            autoComplete="off"
            spellCheck="false"
          />

          <div className="buttons">
            <button type="button" className="btn primary" onClick={runHmac}>
              Tính HMAC
            </button>
            <button type="button" className="btn danger" onClick={clear}>
              Xóa
            </button>
          </div>

          <div className="field">
            <div className="fieldHeader">
              <label htmlFor="hmacOut">Kết quả</label>
              <button
                type="button"
                className="linkButton"
                onClick={() => copyToClipboard(setCopyMessage, hmacResult)}
                disabled={!hmacResult}
                aria-disabled={!hmacResult}
              >
                Copy
              </button>
            </div>
            <textarea id="hmacOut" rows="4" value={hmacResult} readOnly />
            {copyMessage ? <div className="toast">{copyMessage}</div> : null}
            {error ? <div className="error">{error}</div> : null}
          </div>
        </div>
      </div>

      {hashes.length ? (
        <div className="hashGrid" aria-label="Kết quả băm">
          {hashes.map((h) => (
            <div key={h.name} className="hashCard">
              <div className="hashName">{h.name}</div>
              <div className="hashValue">{h.value}</div>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}

