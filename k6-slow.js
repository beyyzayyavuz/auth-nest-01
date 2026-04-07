import http from "k6/http";
import { sleep } from "k6";

export const options = {
  vus: 2,             // Sadece 2 sinsi bot
  duration: "2m",     // 2 dakika boyunca iz bıraksın ki veri setinde görünsün
};

const BASE_URL = "http://localhost:3000";

export default function () {
  const url = `${BASE_URL}/user/profile`; // Genelde profil kontrolü gibi hafif bir yer seçer
  
  const params = {
    headers: {
      "User-Agent": "Bot-Slow-ConstantIAT", // Analiz aşamasında teşhis etmemiz için imza
    },
  };

  // KRİTİK: Tam 2.0 saniye bekleme. 
  // İnsan asla her seferinde tam 2.000ms beklemez.
  sleep(2); 

  http.get(url, params);
  console.log("Sinsi Bot: Periyodik istek gönderildi (IAT=2s)");
}