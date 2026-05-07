// Class-deterministic IP separation YANLIŞ. Botnet-realistic clustering:
// hepsi 192.168.0.0/16 + 10.0.0.0/8 havuzundan, attacker'lar daha küçük
// cluster'lardan ama legit ile overlap.
//
// k6 SharedArray runtime'da her import'ta yeniden değerlendirilemediği için,
// IP havuzlarını function olarak export ediyoruz, scenario'da SharedArray'e
// sarmalanır.

const LEGIT_RANGE = [
  // 50 adet farklı IP — 192.168.x.y aralığı
  ...Array.from({ length: 30 }, (_, i) => `192.168.1.${i + 1}`),
  ...Array.from({ length: 20 }, (_, i) => `10.0.0.${i + 1}`),
];

const ATTACKER_NAIVE = [
  // 20 IP, legit ile overlap'lı
  ...Array.from({ length: 10 }, (_, i) => `192.168.1.${i + 100}`),
  ...Array.from({ length: 5 }, (_, i) => `10.0.0.${i + 50}`),
  ...Array.from({ length: 5 }, (_, i) => `10.0.1.${i + 1}`),
];

const ATTACKER_SOPHISTICATED = [
  // Mimicry: tamamen legit havuzunun içinden + 5 yeni
  ...LEGIT_RANGE.slice(0, 15),
  ...Array.from({ length: 5 }, (_, i) => `192.168.1.${i + 200}`),
];

export function getIpPool(role) {
  switch (role) {
    case 'legit':         return LEGIT_RANGE;
    case 'naive':         return ATTACKER_NAIVE;
    case 'sophisticated': return ATTACKER_SOPHISTICATED;
    default: throw new Error(`Unknown IP role: ${role}`);
  }
}