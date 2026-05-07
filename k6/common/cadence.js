// Box-Muller standart normal
export function standardNormal() {
  const u1 = Math.max(Math.random(), 1e-9);
  const u2 = Math.random();
  return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
}

// Log-normal sample, clamped
// NASA Jul95 fits: μ_log=2.38, σ_log=1.75 — buradan calibrated default
export function lognormalSample(muLog, sigmaLog, minS = 0.3, maxS = 60) {
  const z = standardNormal();
  const s = Math.exp(muLog + sigmaLog * z);
  return Math.min(Math.max(s, minS), maxS);
}

// Think time tiers — NASA-calibrated parametre uçları
export const THINK = {
  // Sayfa içi (form butonları, modal close)
  short:  () => lognormalSample(0.3, 0.6, 0.2, 5),    // medyan ~1.3s
  // Sayfa geçişleri arası (calibrated to NASA mean ~50s, but capped)
  medium: () => lognormalSample(1.2, 0.8, 0.5, 30),   // medyan ~3.3s
  // Uzun okuma (article, video)
  long:   () => lognormalSample(2.0, 0.9, 1.0, 60),   // medyan ~7.4s
};

// Bot cadence — mekanik uniform yerine log-normal (Section 2.6.4 critique)
// Insan'a yakın görünmek için: median benzer (~2.2s), σ daha dar
export function botCadence(meanSec = 2.2, sigma = 0.3) {
  // mean → μ_log = ln(mean) - σ²/2
  const muLog = Math.log(meanSec) - (sigma * sigma) / 2;
  return lognormalSample(muLog, sigma, 0.5, 10);
}

// Zipf rank sampling (search terms vs)
export function zipfSample(n, alpha = 1.0) {
  const u = Math.max(Math.random(), 1e-9);
  const idx = Math.floor(Math.pow(u, -1 / alpha)) - 1;
  return Math.min(idx, n - 1);
}

// Geometric session length
// p=0.72 → mean ~5-6 pages (NASA-calibrated)
export function sessionLength(bouncePr = 0.20, contPr = 0.72, maxN = 15) {
  if (Math.random() < bouncePr) return 1;
  let n = 2;
  while (Math.random() < contPr && n < maxN) n++;
  return n;
}