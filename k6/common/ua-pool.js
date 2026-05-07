// 3-tier UA pool: legit / naive_attacker / sophisticated_attacker
// Sophisticated = legit ile özdeş havuz (mimicry)

export const LEGIT_AGENTS = [
  // StatCounter market share dağılımına yakın, weighted picker'la kullan
  { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36', w: 35 },
  { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36', w: 15 },
  { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15', w: 8 },
  { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0', w: 5 },
  { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0', w: 3 },
  { ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1', w: 18 },
  { ua: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36', w: 10 },
  { ua: 'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36', w: 6 },
];

// Naive attacker: tool-revealing UA (curl, python-requests, Go, scripts)
export const NAIVE_ATTACKER_AGENTS = [
  { ua: 'curl/8.7.1', w: 25 },
  { ua: 'curl/7.81.0', w: 15 },
  { ua: 'python-requests/2.31.0', w: 20 },
  { ua: 'Go-http-client/1.1', w: 15 },
  { ua: 'PostmanRuntime/7.36.0', w: 10 },
  { ua: 'Apache-HttpClient/5.3 (Java/17)', w: 8 },
  { ua: 'aiohttp/3.9.1', w: 7 },
];

// Sophisticated attacker: same as legit (mimicry)
export const SOPHISTICATED_ATTACKER_AGENTS = LEGIT_AGENTS;

// Weighted picker
export function pickWeightedUA(pool) {
  const total = pool.reduce((s, it) => s + it.w, 0);
  let r = Math.random() * total;
  for (const it of pool) {
    r -= it.w;
    if (r <= 0) return it.ua;
  }
  return pool[pool.length - 1].ua;
}

// Accept-Language ve Accept-Encoding havuzları
export const ACCEPT_LANGS = [
  'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
  'tr,en-US;q=0.9,en;q=0.8',
  'en-US,en;q=0.9',
  'en-GB,en;q=0.9,tr;q=0.8',
  'tr-TR,tr;q=0.9',
];

export const ACCEPT_ENCS = [
  'gzip, deflate, br',
  'gzip, deflate, br, zstd',
  'gzip, deflate',
];

export function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}