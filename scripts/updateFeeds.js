// scripts/updateFeeds.js
const axios = require('axios');
const fs    = require('fs');
const path  = require('path');

const SOURCES = [
  { name: 'MIT Phishing DB', url: 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt' },
  { name: 'Phishing Army Ext.', url: 'https://phishing.army/download/phishing_army_blocklist_extended.txt' },
  { name: 'Emerging Threats', url: 'https://hosts.tweedge.net/malicious.txt' },
  { name: 'URLhaus Hostfile', url: 'https://urlhaus.abuse.ch/downloads/hostfile/' }
];

const OUT_DIR  = path.join(__dirname, '../data');
const OUT_FILE = path.join(OUT_DIR, 'phishingList.json');

// Extrai apenas domínios/URLs válidos de cada feed
function parseLines(text) {
  return text
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && /^[a-z0-9]/i.test(l));
}

async function updateFeeds() {
  let all = new Set();

  for (let src of SOURCES) {
    try {
      console.log(`⏳ Baixando ${src.name} de ${src.url}`);
      const res = await axios.get(src.url, { responseType: 'text', timeout: 30_000 });
      const items = parseLines(res.data);
      items.forEach(i => all.add(i));
      console.log(`✅ ${src.name}: ${items.length} entradas`);
    } catch (err) {
      console.error(`❌ Erro em ${src.name}:`, err.message);
    }
  }

  const combined = Array.from(all);
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify(combined, null, 2), 'utf-8');
  console.log(`🎉 Total único: ${combined.length} domínios/URLs salvos em data/phishingList.json`);
}

updateFeeds();
