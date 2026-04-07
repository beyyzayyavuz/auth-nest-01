import http from "k6/http";
import { sleep } from "k6";
import { randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

export const options = {
  vus: 5,           // Az ama öz gerçek kullanıcı
  duration: "5m",    // 5 dakika boyunca aksın (En az 1000 satır hedefliyoruz)
};

const BASE_URL = "http://localhost:3000";

export default function () {
  // Rastgele Endpoint Seçimi (ENTROPİ ANALİZİ İÇİN)
  const rand = Math.random();
  const params = { headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0-User" } };

  if (rand < 0.4) {
    // %40 Düşük Maliyetli GET isteği
    http.get(`${BASE_URL}/user/profile`, params);
    console.log("Normal User: Browsing Profile");
  } else if (rand < 0.7) {
    // %30 Orta Maliyetli Login
    const payload = JSON.stringify({ email: `user${randomIntBetween(1,100)}@test.com`, password: "123" });
    http.post(`${BASE_URL}/auth/login`, payload, params);
    console.log("Normal User: Logging In");
  } else {
    // %30 Yüksek Maliyetli Register
    const userNum = randomIntBetween(1, 100000);
    const payload = JSON.stringify({ email: `new${userNum}@test.com`, password: "123", name: "User" });
    http.post(`${BASE_URL}/auth/register`, payload, params);
    console.log("Normal User: Registering");
  }

  // RASTGELE IAT (İnsan Beklemesi) - Varyans burada oluşacak
  sleep(randomIntBetween(2, 8)); 
}