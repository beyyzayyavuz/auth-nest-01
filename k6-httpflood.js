import http from "k6/http";

export const options = {
  vus: 50,           // 50 eşzamanlı saldırgan
  duration: "30s",   // 30 saniye boyunca (Sunucu muhtemelen daha erken çöker)
};

const BASE_URL = "http://localhost:3000";

export default function () {
  const url = `${BASE_URL}/auth/login`;
  
  // EN AĞIR ENDPOINT: Login (Bcrypt şifre doğrulama CPU'yu bitirir)
  const payload = JSON.stringify({
    email: "attack-victim@test.com",
    password: "wrong-password-123"
  });

  const params = {
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "Bot-Flood-HighCost" // Python'da bu etiketi saniyeler içinde yakalayacağız
    },
  };

  // IAT (İstek Arası Süre) burada milisaniyeler düzeyinde olacak.
  // Hiç sleep() koymuyoruz ki "Flood" etkisi yaratsın.
  http.post(url, payload, params);
}