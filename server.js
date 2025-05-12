// server.js
const http        = require('http');
const urlModule   = require('url');
const fs          = require('fs');
const path        = require('path');
const whoisJson   = require('whois-json');
const sslChecker  = require('ssl-checker');
const levenshtein = require('fast-levenshtein');
const tf          = require('@tensorflow/tfjs-node');
const static      = require('node-static');
const geoip       = require('geoip-lite');

const PORT       = 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const fileServer = new static.Server(PUBLIC_DIR, { cache: 0 });

// 1) Carrega phishingList como Set
const phishingArray = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'data/phishingList.json'), 'utf-8')
);
const phishingList = new Set(phishingArray);

// 2) Configs
const brandDomains     = ['google.com','facebook.com','paypal.com','amazon.com','bankofamerica.com'];
const phishingKeywords = ['login','secure','account','verify','bank','password','update','free','click'];

// 3) Carrega modelo ML
let mlModel = null;
tf.loadLayersModel(`file://${path.join(__dirname,'model/model.json')}`)
  .then(m => {
    mlModel = m;
    console.log('✅ Modelo ML carregado.');
  })
  .catch(err => console.error('❌ Falha ao carregar modelo ML:', err));

// 4) Carrega scaler
const scaler = JSON.parse(
  fs.readFileSync(path.join(__dirname,'model/scaler.json'),'utf-8')
);
const { mins, maxs } = scaler;

// 5) Normalização min–max
function normalize(feats) {
  return feats.map((v,i) =>
    (v - mins[i]) / (maxs[i] - mins[i] + 1e-6)
  );
}

// 6) Extrai hostname
function getHostname(u) {
  try { return new URL(u).hostname.toLowerCase(); }
  catch {
    try { return new URL('http://' + u).hostname.toLowerCase(); }
    catch { return null; }
  }
}

// 7) Extrai as 7 features (incluindo inListFlag via Set.has)
function extractMLFeatures(u) {
  const hostname     = getHostname(u) || '';
  const length       = u.length;
  const dots         = (hostname.match(/\./g) || []).length;
  const specialChars = (u.match(/[^a-zA-Z0-9]/g) || []).length;

  // contagem de keywords
  const lower = u.toLowerCase();
  let keywordCount = 0;
  phishingKeywords.forEach(kw => {
    if (lower.includes(kw)) keywordCount++;
  });

  // GeoIP: país como soma de charCodes
  const lookup = geoip.lookup(hostname) || {};
  const cc     = lookup.country || 'UN';
  let countryNum = 0;
  for (let i = 0; i < cc.length; i++) countryNum += cc.charCodeAt(i);

  // typosquatting
  const minLev = Math.min(
    ...brandDomains.map(b => levenshtein.get(hostname, b))
  );
  const typoFlag = minLev <= 3 ? 1 : 0;

  // flag de lista de phishing
  const inListFlag = phishingList.has(hostname) ? 1 : 0;

  return [
    length,        // 0
    dots,          // 1
    specialChars,  // 2
    keywordCount,  // 3
    countryNum,    // 4
    typoFlag,      // 5
    inListFlag     // 6
  ];
}

// 8) Função principal de análise
async function analyzeUrl(targetUrl) {
  const hostname = getHostname(targetUrl);
  if (!hostname) throw new Error('URL inválida');

  // — Heurísticas —
  const inList = phishingList.has(hostname);

  let ageDays = null, sslValid = null, sslDaysRemaining = null;
  try {
    const whois = await whoisJson(hostname);
    if (whois.creationDate) {
      ageDays = Math.floor((Date.now() - new Date(whois.creationDate)) / 864e5);
    }
  } catch {}
  try {
    const info = await sslChecker(hostname, { method:'GET', port:443 });
    sslValid         = info.valid;
    sslDaysRemaining = info.daysRemaining;
  } catch {}
  const minLev = Math.min(
    ...brandDomains.map(b => levenshtein.get(hostname, b))
  );

  let score = 0;
  const explanation = [];
  if (inList) {
    score = 100;
    explanation.push('Hostname em lista de phishing conhecida.');
  } else {
    if (ageDays !== null) {
      if (ageDays < 30)      { score += 20; explanation.push(`Domínio jovem (${ageDays} dias)`); }
      else if (ageDays < 365){ score += 10; explanation.push(`Domínio <1 ano (${ageDays} dias)`); }
    }
    if (sslValid === false)    { score += 20; explanation.push('SSL inválido'); }
    else if (sslDaysRemaining !== null && sslDaysRemaining < 30) {
      score += 10; explanation.push(`SSL expira em ${sslDaysRemaining} dias`);
    }
    if (minLev <= 3)           { score += 15; explanation.push(`Typosquatting (LEV=${minLev})`); }
    else if (minLev <= 5)      { score += 5;  explanation.push(`Domínio similar (LEV=${minLev})`); }
  }
  score = Math.min(score, 100);

  // — ML —
  let mlProb = null, mlRisk = null, mlFeatures = null;
  if (mlModel) {
    const raw  = extractMLFeatures(targetUrl);
    mlFeatures = {
      length:        raw[0],
      subdomains:    raw[1],
      specialChars:  raw[2],
      keywordCount:  raw[3],
      countryNum:    raw[4],
      typoSquatting: raw[5],
      inListFlag:    raw[6]
    };
    const norm  = normalize(raw);
    const input = tf.tensor2d([norm]);
    const pred  = await mlModel.predict(input).data();
    input.dispose();

    mlProb = pred[0];
    mlRisk = Math.round(mlProb * 100);
    explanation.push(`ML risk: ${mlRisk}%`);
    score = Math.round(score * 0.6 + mlRisk * 0.4);
  }

  return {
    hostname,
    isPhishing: inList || score > 50,
    riskScore: score,
    heuristics: { inList, ageDays, sslValid, sslDaysRemaining, minLevenshtein: minLev },
    ml: { mlProb, mlRisk, mlFeatures },
    explanation
  };
}

// 9) Servidor HTTP + serve static
const server = http.createServer(async (req, res) => {
  const { pathname, query } = urlModule.parse(req.url, true);

  if (pathname === '/check') {
    const url = query.url;
    if (!url) {
      res.writeHead(400, {'Content-Type':'application/json','Access-Control-Allow-Origin':'*'});
      return res.end(JSON.stringify({ error:'Parâmetro url é obrigatório' }));
    }
    try {
      const result = await analyzeUrl(url);
      res.writeHead(200, {'Content-Type':'application/json','Access-Control-Allow-Origin':'*'});
      return res.end(JSON.stringify({ url, ...result }, null, 2));
    } catch (err) {
      res.writeHead(400, {'Content-Type':'application/json','Access-Control-Allow-Origin':'*'});
      return res.end(JSON.stringify({ error: err.message }));
    }
  }

  req.addListener('end', () => fileServer.serve(req, res)).resume();
});

server.listen(PORT, () => {
  console.log(`🚀 Phish Detector rodando em http://localhost:${PORT}`);
});
