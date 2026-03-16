import React, { useMemo, useState } from "react";
import {
  ASYMMETRIC_ALGO,
  asymmetricInfo,
  ecdhDemo,
  generateRsaOaepKeyPair,
  generateRsaPssKeyPair,
  hybridEncryptDecrypt,
  rsaOaepEncryptDecrypt,
  rsaPssSignVerify,
} from "../crypto/webcrypto";

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

export default function AsymmetricTab() {
  const [algo, setAlgo] = useState(ASYMMETRIC_ALGO.RSA_OAEP);
  const [plainText, setPlainText] = useState("");

  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [copyMessage, setCopyMessage] = useState("");

  const [rsaOaepKeyPair, setRsaOaepKeyPair] = useState({ publicKey: null, privateKey: null, publicPem: "" });
  const [rsaPssKeyPair, setRsaPssKeyPair] = useState({ publicKey: null, privateKey: null, publicPem: "" });

  const info = useMemo(() => asymmetricInfo(algo), [algo]);

  const clear = () => {
    setPlainText("");
    setResult("");
    setError("");
    setCopyMessage("");
  };

  const generateKeys = async () => {
    setCopyMessage("");
    setError("");
    if (algo === ASYMMETRIC_ALGO.RSA_OAEP || algo === ASYMMETRIC_ALGO.HYBRID_RSA_AES) {
      const res = await generateRsaOaepKeyPair();
      if (!res.ok) {
        setError(res.error || "Không thể tạo keypair.");
        return;
      }
      setRsaOaepKeyPair(res.value);
      return;
    }

    if (algo === ASYMMETRIC_ALGO.RSA_PSS) {
      const res = await generateRsaPssKeyPair();
      if (!res.ok) {
        setError(res.error || "Không thể tạo keypair.");
        return;
      }
      setRsaPssKeyPair(res.value);
    }
  };

  const run = async (mode) => {
    setCopyMessage("");
    setError("");

    if (algo === ASYMMETRIC_ALGO.RSA_OAEP) {
      const res = await rsaOaepEncryptDecrypt({ mode, text: plainText, keyPair: rsaOaepKeyPair });
      if (!res.ok) {
        setResult("");
        setError(res.error || "Thao tác thất bại.");
        return;
      }
      setResult(res.value || "");
      return;
    }

    if (algo === ASYMMETRIC_ALGO.HYBRID_RSA_AES) {
      const res = await hybridEncryptDecrypt({ mode, text: plainText, keyPair: rsaOaepKeyPair });
      if (!res.ok) {
        setResult("");
        setError(res.error || "Thao tác thất bại.");
        return;
      }
      setResult(res.value || "");
      return;
    }

    if (algo === ASYMMETRIC_ALGO.RSA_PSS) {
      const res =
        mode === "encrypt"
          ? await rsaPssSignVerify({ mode: "sign", text: plainText, signatureBase64: "", keyPair: rsaPssKeyPair })
          : await rsaPssSignVerify({
              mode: "verify",
              text: plainText,
              signatureBase64: result,
              keyPair: rsaPssKeyPair,
            });
      if (!res.ok) {
        if (mode === "encrypt") setResult("");
        setError(res.error || "Thao tác thất bại.");
        return;
      }
      setResult(res.value || "");
      return;
    }

    if (algo === ASYMMETRIC_ALGO.ECDH) {
      const res = await ecdhDemo();
      if (!res.ok) {
        setResult("");
        setError(res.error || "Thao tác thất bại.");
        return;
      }
      setResult(res.value || "");
      return;
    }
  };

  const hint =
    algo === ASYMMETRIC_ALGO.HYBRID_RSA_AES
      ? "Encrypt: plaintext | Decrypt: JSON payload"
      : algo === ASYMMETRIC_ALGO.RSA_OAEP
        ? "Encrypt: plaintext | Decrypt: Base64"
        : algo === ASYMMETRIC_ALGO.RSA_PSS
          ? "Sign/Verify: plaintext (Verify dùng chữ ký ở ô Kết quả)"
          : "Nhấn chạy để demo ECDH";

  const showGenerate =
    algo === ASYMMETRIC_ALGO.RSA_OAEP || algo === ASYMMETRIC_ALGO.HYBRID_RSA_AES || algo === ASYMMETRIC_ALGO.RSA_PSS;

  const keyBox =
    algo === ASYMMETRIC_ALGO.RSA_PSS
      ? rsaPssKeyPair
      : algo === ASYMMETRIC_ALGO.RSA_OAEP || algo === ASYMMETRIC_ALGO.HYBRID_RSA_AES
        ? rsaOaepKeyPair
        : null;

  return (
    <section className="tabContent active">
      <div className="algoInfo">{info}</div>

      <div className="field">
        <label htmlFor="asymAlgo">Giải thuật</label>
        <select id="asymAlgo" value={algo} onChange={(e) => setAlgo(e.target.value)}>
          <optgroup label="RSA">
            <option value={ASYMMETRIC_ALGO.RSA_OAEP}>RSA-OAEP (Encrypt/Decrypt)</option>
            <option value={ASYMMETRIC_ALGO.HYBRID_RSA_AES}>Session key encryption (AES-GCM + RSA-OAEP)</option>
            <option value={ASYMMETRIC_ALGO.RSA_PSS}>Digital Signature (RSA-PSS Sign/Verify)</option>
          </optgroup>
          <optgroup label="Key agreement">
            <option value={ASYMMETRIC_ALGO.ECDH}>Diffie–Hellman kiểu (ECDH P-256 demo)</option>
          </optgroup>
        </select>
      </div>

      {showGenerate ? (
        <div className="buttons">
          <button type="button" className="btn warning" onClick={generateKeys}>
            {algo === ASYMMETRIC_ALGO.RSA_PSS ? "Tạo RSA-PSS keypair" : "Tạo RSA-OAEP keypair"}
          </button>
        </div>
      ) : null}

      {keyBox?.publicPem ? (
        <div className="rsaKeys">
          <div className="rsaKeyBox">
            <label>Public key (PEM)</label>
            <span>{keyBox.publicPem}</span>
          </div>
          <div className="rsaKeyBox">
            <label>Private key</label>
            <span>{keyBox.privateKey ? "Đã tạo (lưu trong RAM)" : "Chưa có"}</span>
          </div>
        </div>
      ) : null}

      <div className="grid">
        <div className="field">
          <div className="fieldHeader">
            <label htmlFor="asymIn">Văn bản đầu vào</label>
            <span className="hint">{hint}</span>
          </div>
          <textarea
            id="asymIn"
            rows="7"
            value={plainText}
            onChange={(e) => setPlainText(e.target.value)}
            placeholder="Nhập dữ liệu…"
          />
        </div>

        <div className="field">
          <div className="fieldHeader">
            <label htmlFor="asymOut">Kết quả</label>
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
          <textarea id="asymOut" rows="7" value={result} readOnly />
          {copyMessage ? <div className="toast">{copyMessage}</div> : null}
          {error ? <div className="error">{error}</div> : null}
        </div>
      </div>

      <div className="buttons">
        {algo === ASYMMETRIC_ALGO.RSA_PSS ? (
          <>
            <button type="button" className="btn success" onClick={() => run("encrypt")}>
              Sign
            </button>
            <button type="button" className="btn primary" onClick={() => run("decrypt")}>
              Verify
            </button>
          </>
        ) : algo === ASYMMETRIC_ALGO.ECDH ? (
          <button type="button" className="btn primary" onClick={() => run("encrypt")}>
            Tạo shared secret
          </button>
        ) : (
          <>
            <button type="button" className="btn success" onClick={() => run("encrypt")}>
              Encrypt
            </button>
            <button type="button" className="btn primary" onClick={() => run("decrypt")}>
              Decrypt
            </button>
          </>
        )}
        <button type="button" className="btn danger" onClick={clear}>
          Xóa
        </button>
      </div>
    </section>
  );
}

