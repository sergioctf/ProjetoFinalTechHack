// scripts/checkSamples.js
const tf = require('@tensorflow/tfjs-node');
const fs = require('fs');
const path = require('path');
const levenshtein = require('fast-levenshtein');

// 1) Configurações (mesmas do server.js)
const phishingKeywords = [
  'login','secure','account','verify','bank',
  'password','update','free','click'
];
const brandDomains = [
  'google.com','facebook.com','paypal.com',
  'amazon.com','bankofamerica.com'
];

// 2) Carrega scaler (mins/maxs) e modelo
const scaler = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../model/scaler.json'), 'utf-8')
);
const { mins, maxs } = scaler;

async function main() {
  const model = await tf.loadLayersModel(
    `file://${path.join(__dirname, '../model/model.json')}`
  );

  // 3) Funções auxiliares
  function normalize(feats) {
    return feats.map((v,i) =>
      (v - mins[i]) / (maxs[i] - mins[i] + 1e-6)
    );
  }

  function getHostname(u) {
    try { return new URL(u).hostname.toLowerCase(); }
    catch {
      try { return new URL('http://' + u).hostname.toLowerCase(); }
      catch { return ''; }
    }
  }

  function extractFeatures(u) {
    const hostname     = getHostname(u);
    const length       = u.length;
    const dots         = (hostname.match(/\./g) || []).length;
    const hasDigit     = /\d/.test(u) ? 1 : 0;
    const hasAt        = u.includes('@') ? 1 : 0;
    const specialChars = (u.match(/[^a-zA-Z0-9]/g) || []).length;
    const lower        = u.toLowerCase();
    const keywordCount = phishingKeywords.reduce(
      (sum, kw) => sum + (lower.includes(kw) ? 1 : 0), 0
    );
    // ageFlag e sslFlag aqui não importam para o ML
    const ageFlag      = 0;
    const sslFlag      = 0;
    const minLev = brandDomains
      .map(b => levenshtein.get(hostname, b))
      .reduce((a,b) => Math.min(a,b), Infinity);
    const typoFlag     = minLev <= 3 ? 1 : 0;

    return [
      length, dots, hasDigit, hasAt,
      specialChars, keywordCount,
      ageFlag, sslFlag, typoFlag
    ];
  }

  // 4) URLs de teste
  const samples = [
    'https://google.com',
    'https://github.com',
    'https://wikipedia.org',
    'https://example.com',
    'http://malicious-phish.suspicious'
  ];

  console.log('\n📊 Resultados do ML para amostras:\n');
  for (let url of samples) {
    const raw = extractFeatures(url);
    const norm = normalize(raw);
    const input = tf.tensor2d([norm]);
    const prob  = (await model.predict(input).data())[0];
    input.dispose();
    console.log(
      `${url.padEnd(40)} → ML prob: ${(prob*100).toFixed(2)}%`
    );
  }
}

main().catch(err => {
  console.error('❌ Erro no checkSamples.js:', err.message);
  process.exit(1);
});
