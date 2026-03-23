import React, { useMemo, useState } from "react";
import { e2eeDecrypt, e2eeEncrypt, e2eeInfo, generateIdentityKeyPair } from "../crypto/e2ee";

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

export default function E2EETab() {
  const info = useMemo(() => e2eeInfo(), []);

  const [alice, setAlice] = useState({ publicKey: null, privateKey: null, publicKeyBase64: "" });
  const [bob, setBob] = useState({ publicKey: null, privateKey: null, publicKeyBase64: "" });

  const [aPlain, setAPlain] = useState("");
  const [aCipher, setACipher] = useState("");
  const [aDecrypted, setADecrypted] = useState("");

  const [bPlain, setBPlain] = useState("");
  const [bCipher, setBCipher] = useState("");
  const [bDecrypted, setBDecrypted] = useState("");

  const [error, setError] = useState("");
  const [copyMessage, setCopyMessage] = useState("");

  const clear = () => {
    setAPlain("");
    setACipher("");
    setADecrypted("");
    setBPlain("");
    setBCipher("");
    setBDecrypted("");
    setError("");
    setCopyMessage("");
  };

  const genAlice = async () => {
    setError("");
    const res = await generateIdentityKeyPair();
    if (!res.ok) return setError(res.error || "Không thể tạo keypair.");
    setAlice(res.value);
  };

  const genBob = async () => {
    setError("");
    const res = await generateIdentityKeyPair();
    if (!res.ok) return setError(res.error || "Không thể tạo keypair.");
    setBob(res.value);
  };

  const encryptAliceToBob = async () => {
    setError("");
    const res = await e2eeEncrypt({
      plaintext: aPlain,
      from: "Alice",
      to: "Bob",
      recipientPublicKeyBase64: bob.publicKeyBase64,
    });
    if (!res.ok) return setError(res.error || "Encrypt thất bại.");
    setACipher(res.value || "");
  };

  const decryptAtBob = async () => {
    setError("");
    const res = await e2eeDecrypt({ payloadJson: aCipher, recipientPrivateKey: bob.privateKey });
    if (!res.ok) return setError(res.error || "Decrypt thất bại.");
    setADecrypted(res.value || "");
  };

  const encryptBobToAlice = async () => {
    setError("");
    const res = await e2eeEncrypt({
      plaintext: bPlain,
      from: "Bob",
      to: "Alice",
      recipientPublicKeyBase64: alice.publicKeyBase64,
    });
    if (!res.ok) return setError(res.error || "Encrypt thất bại.");
    setBCipher(res.value || "");
  };

  const decryptAtAlice = async () => {
    setError("");
    const res = await e2eeDecrypt({ payloadJson: bCipher, recipientPrivateKey: alice.privateKey });
    if (!res.ok) return setError(res.error || "Decrypt thất bại.");
    setBDecrypted(res.value || "");
  };

  return (
    <section className="tabContent active">
      <div className="algoInfo">{info}</div>

      <div className="buttons">
        <button type="button" className="btn warning" onClick={genAlice}>
          Tạo khóa Alice
        </button>
        <button type="button" className="btn warning" onClick={genBob}>
          Tạo khóa Bob
        </button>
        <button type="button" className="btn danger" onClick={clear}>
          Xóa
        </button>
      </div>

      {(alice.publicKeyBase64 || bob.publicKeyBase64) && (
        <div className="e2eeKeys">
          <div className="e2eeKeyBox">
            <label>Alice public key (raw, Base64)</label>
            <span>{alice.publicKeyBase64 || "Chưa có"}</span>
          </div>
          <div className="e2eeKeyBox">
            <label>Bob public key (raw, Base64)</label>
            <span>{bob.publicKeyBase64 || "Chưa có"}</span>
          </div>
        </div>
      )}

      <div className="grid">
        <div className="field">
          <div className="fieldHeader">
            <label htmlFor="aPlain">Alice → Bob (Plaintext)</label>
            <span className="hint">Encrypt bằng public key Bob</span>
          </div>
          <textarea
            id="aPlain"
            rows="6"
            value={aPlain}
            onChange={(e) => setAPlain(e.target.value)}
            placeholder="Nhập tin nhắn Alice gửi Bob…"
          />
          <div className="buttons">
            <button type="button" className="btn success" onClick={encryptAliceToBob}>
              Encrypt (Alice)
            </button>
          </div>
        </div>

        <div className="field">
          <div className="fieldHeader">
            <label htmlFor="aCipher">Ciphertext payload (JSON)</label>
            <button type="button" className="linkButton" onClick={() => copyToClipboard(setCopyMessage, aCipher)} disabled={!aCipher}>
              Copy
            </button>
          </div>
          <textarea
            id="aCipher"
            rows="6"
            value={aCipher}
            onChange={(e) => setACipher(e.target.value)}
            placeholder="Payload JSON sẽ xuất hiện ở đây (hoặc bạn có thể dán payload vào để thử decrypt)…"
          />
          <div className="buttons">
            <button type="button" className="btn primary" onClick={decryptAtBob}>
              Decrypt (Bob)
            </button>
          </div>
          <div className="field">
            <div className="fieldHeader">
              <label htmlFor="aDecrypted">Bob nhận được</label>
              <button
                type="button"
                className="linkButton"
                onClick={() => copyToClipboard(setCopyMessage, aDecrypted)}
                disabled={!aDecrypted}
              >
                Copy
              </button>
            </div>
            <textarea id="aDecrypted" rows="4" value={aDecrypted} readOnly />
          </div>
        </div>
      </div>

      <div className="grid">
        <div className="field">
          <div className="fieldHeader">
            <label htmlFor="bPlain">Bob → Alice (Plaintext)</label>
            <span className="hint">Encrypt bằng public key Alice</span>
          </div>
          <textarea
            id="bPlain"
            rows="6"
            value={bPlain}
            onChange={(e) => setBPlain(e.target.value)}
            placeholder="Nhập tin nhắn Bob gửi Alice…"
          />
          <div className="buttons">
            <button type="button" className="btn success" onClick={encryptBobToAlice}>
              Encrypt (Bob)
            </button>
          </div>
        </div>

        <div className="field">
          <div className="fieldHeader">
            <label htmlFor="bCipher">Ciphertext payload (JSON)</label>
            <button type="button" className="linkButton" onClick={() => copyToClipboard(setCopyMessage, bCipher)} disabled={!bCipher}>
              Copy
            </button>
          </div>
          <textarea
            id="bCipher"
            rows="6"
            value={bCipher}
            onChange={(e) => setBCipher(e.target.value)}
            placeholder="Payload JSON sẽ xuất hiện ở đây (hoặc bạn có thể dán payload vào để thử decrypt)…"
          />
          <div className="buttons">
            <button type="button" className="btn primary" onClick={decryptAtAlice}>
              Decrypt (Alice)
            </button>
          </div>
          <div className="field">
            <div className="fieldHeader">
              <label htmlFor="bDecrypted">Alice nhận được</label>
              <button
                type="button"
                className="linkButton"
                onClick={() => copyToClipboard(setCopyMessage, bDecrypted)}
                disabled={!bDecrypted}
              >
                Copy
              </button>
            </div>
            <textarea id="bDecrypted" rows="4" value={bDecrypted} readOnly />
          </div>
        </div>
      </div>

      {copyMessage ? <div className="toast">{copyMessage}</div> : null}
      {error ? <div className="error">{error}</div> : null}
    </section>
  );
}

