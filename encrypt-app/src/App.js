import React, { useState } from "react";
import "./App.css";
import AnalysisTab from "./components/AnalysisTab";
import AsymmetricTab from "./components/AsymmetricTab";
import E2EETab from "./components/E2EETab";
import HashTab from "./components/HashTab";
import SymmetricTab from "./components/SymmetricTab";

function App() {
  const [tab, setTab] = useState("symmetric");

  return (
    <div className="app">
      <header className="appHeader">
        <h1>Ứng dụng Mã hóa (HW)</h1>
        <p>Chọn giải thuật để mã hóa/giải mã, băm, MAC hoặc demo bất đối xứng.</p>
      </header>
      <main className="card">
        <div className="tabs" role="tablist" aria-label="Chức năng">
          <button
            type="button"
            className={`tab ${tab === "symmetric" ? "active" : ""}`}
            onClick={() => setTab("symmetric")}
          >
            Mã hóa đối xứng
          </button>
          <button
            type="button"
            className={`tab ${tab === "asymmetric" ? "active" : ""}`}
            onClick={() => setTab("asymmetric")}
          >
            Bất đối xứng
          </button>
          <button type="button" className={`tab ${tab === "e2ee" ? "active" : ""}`} onClick={() => setTab("e2ee")}>
            E2EE
          </button>
          <button type="button" className={`tab ${tab === "hash" ? "active" : ""}`} onClick={() => setTab("hash")}>
            Băm / MAC
          </button>
          <button
            type="button"
            className={`tab ${tab === "analysis" ? "active" : ""}`}
            onClick={() => setTab("analysis")}
          >
            Phân tích
          </button>
        </div>

        {tab === "symmetric" ? <SymmetricTab /> : null}
        {tab === "asymmetric" ? <AsymmetricTab /> : null}
        {tab === "e2ee" ? <E2EETab /> : null}
        {tab === "hash" ? <HashTab /> : null}
        {tab === "analysis" ? <AnalysisTab /> : null}
      </main>

      <footer className="footer">
        <span>
          Lưu ý: các thuật toán “cổ điển”, DES và các demo là để học tập. Dùng AES-GCM/ChaCha20 + key quản lý đúng
          cách cho ứng dụng thực tế.
        </span>
      </footer>
    </div>
  );
}

export default App;
