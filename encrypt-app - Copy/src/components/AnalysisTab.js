import React, { useMemo, useState } from "react";
import { frequencyAnalysis } from "../crypto/analysis";

export default function AnalysisTab() {
  const [text, setText] = useState("");
  const analysis = useMemo(() => frequencyAnalysis(text), [text]);

  return (
    <section className="tabContent active">
      <div className="algoInfo">Frequency Analysis: đếm tần suất chữ cái A–Z (hữu ích khi phá substitution cipher).</div>

      <div className="grid">
        <div className="field">
          <label htmlFor="analysisInput">Văn bản</label>
          <textarea
            id="analysisInput"
            rows="7"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Nhập văn bản để phân tích…"
          />
        </div>

        <div className="field">
          <div className="fieldHeader">
            <label htmlFor="analysisOut">Kết quả</label>
            <span className="hint">Tổng chữ cái: {analysis.total}</span>
          </div>
          <textarea
            id="analysisOut"
            rows="7"
            value={analysis.items
              .slice(0, 26)
              .map((x) => `${x.ch}: ${x.count} (${x.pct.toFixed(2)}%)`)
              .join("\n")}
            readOnly
          />
        </div>
      </div>
    </section>
  );
}

