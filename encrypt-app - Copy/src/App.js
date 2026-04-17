import React from "react";
import "./App.css";
import SymmetricTab from "./components/SymmetricTab";

function App() {
  return (
    <div className="app">
      <header className="appHeader">
        <h1>Ứng dụng Mã hóa Đối xứng</h1>
        <p>Mã hóa và giải mã bằng thuật toán đối xứng.</p>
      </header>
      <main className="card">
        <SymmetricTab />
      </main>

      <footer className="footer">
        <span>
          Lưu ý: các thuật toán “cổ điển”, DES và các demo là để học tập. Dùng
          AES-GCM/ChaCha20 + key quản lý đúng cách cho ứng dụng thực tế.
        </span>
      </footer>
    </div>
  );
}

export default App;
