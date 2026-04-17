export function frequencyAnalysis(text) {
  const counts = new Map();
  let total = 0;
  for (const ch of (text || "").toUpperCase()) {
    if (ch < "A" || ch > "Z") continue;
    total += 1;
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  const items = Array.from(counts.entries())
    .map(([ch, count]) => ({ ch, count, pct: total ? (count / total) * 100 : 0 }))
    .sort((a, b) => b.count - a.count || (a.ch < b.ch ? -1 : 1));
  return { total, items };
}

