// scripts/trainModel.js
const tf         = require('@tensorflow/tfjs-node');
const fs         = require('fs');
const path       = require('path');
const lev        = require('fast-levenshtein');
const geoip      = require('geoip-lite');

// 1) Paths
const PHISHING_JSON = path.join(__dirname, '../data/phishingList.json');
const LEGIT_JSON    = path.join(__dirname, '../data/legitList.json');
const MODEL_DIR     = path.join(__dirname, '../model');

// 2) Carrega listas
const phishingList = JSON.parse(fs.readFileSync(PHISHING_JSON, 'utf-8'));
const legitList    = JSON.parse(fs.readFileSync(LEGIT_JSON,    'utf-8'));

// 3) Parâmetros
const phishingKeywords = ['login','secure','account','verify','bank','password','update','free','click'];
const brandDomains     = ['google.com','facebook.com','paypal.com','amazon.com','bankofamerica.com'];

// 4) Helpers síncronos
function getHostname(u) {
  try { return new URL(u).hostname.toLowerCase(); }
  catch {
    try { return new URL('http://' + u).hostname.toLowerCase(); }
    catch { return ''; }
  }
}

// 5) Extrai 7 features (incl. inListFlag)
function extractFeatures(u) {
  const hostname     = getHostname(u);
  const length       = u.length;
  const dots         = (hostname.match(/\./g) || []).length;
  const specialChars = (u.match(/[^a-zA-Z0-9]/g) || []).length;

  // palavras-chave
  const lower = u.toLowerCase();
  let keywordCount = 0;
  phishingKeywords.forEach(kw => {
    if (lower.includes(kw)) keywordCount++;
  });

  // GeoIP país numérico
  const lookup = geoip.lookup(hostname) || {};
  const cc     = lookup.country || 'UN';
  let countryNum = 0;
  for (let i = 0; i < cc.length; i++) countryNum += cc.charCodeAt(i);

  // typosquatting
  const minLev = brandDomains
    .map(b => lev.get(hostname, b))
    .reduce((a,b) => a < b ? a : b, Infinity);
  const typoFlag = minLev <= 3 ? 1 : 0;

  // NOVA feature: presença na lista de phishing
  const inListFlag = phishingList.includes(hostname) ? 1 : 0;

  return [
    length,        // 0
    dots,          // 1
    specialChars,  // 2
    keywordCount,  // 3
    countryNum,    // 4
    typoFlag,      // 5
    inListFlag     // 6   <-- feature nova
  ];
}

async function buildDataset() {
  // undersample phishing para igualar legit
  const sampleSize = legitList.length;
  const phishSample = phishingList
    .sort(() => Math.random() - 0.5)
    .slice(0, sampleSize);

  const urls   = phishSample.concat(legitList);
  const labels = phishSample.map(() => 1).concat(legitList.map(() => 0));

  console.log(`🔧 Extraindo features de ${urls.length} URLs...`);
  const dataRaw = urls.map(extractFeatures);

  // min–max normalization
  const numFeat = dataRaw[0].length;
  const mins = Array(numFeat).fill(Infinity);
  const maxs = Array(numFeat).fill(-Infinity);
  dataRaw.forEach(row => row.forEach((v,i) => {
    if (v < mins[i]) mins[i] = v;
    if (v > maxs[i]) maxs[i] = v;
  }));
  const dataNorm = dataRaw.map(row =>
    row.map((v,i) => (v - mins[i]) / (maxs[i] - mins[i] + 1e-6))
  );

  // salva scaler
  if (!fs.existsSync(MODEL_DIR)) fs.mkdirSync(MODEL_DIR);
  fs.writeFileSync(
    path.join(MODEL_DIR,'scaler.json'),
    JSON.stringify({ mins, maxs }, null, 2),
    'utf-8'
  );

  const xs = tf.tensor2d(dataNorm);
  const ys = tf.tensor1d(labels, 'int32');
  return { xs, ys };
}

async function train() {
  const { xs, ys } = await buildDataset();
  console.log(`🚀 Treinando com ${xs.shape[0]} exemplos e ${xs.shape[1]} features`);

  // modelo simples
  const model = tf.sequential();
  model.add(tf.layers.dense({ units: 16, activation:'relu', inputShape:[xs.shape[1]] }));
  model.add(tf.layers.dense({ units: 8,  activation:'relu' }));
  model.add(tf.layers.dense({ units: 1,  activation:'sigmoid' }));

  model.compile({
    optimizer: 'adam',
    loss: 'binaryCrossentropy',
    metrics: ['accuracy']
  });

  await model.fit(xs, ys, {
    epochs: 20,
    batchSize: 64,
    validationSplit: 0.2,
    callbacks: {
      onEpochEnd: (e, log) => {
        console.log(`Epoch ${e+1}: loss=${log.loss.toFixed(3)}, acc=${log.acc.toFixed(3)}, val_acc=${log.val_pred?log.val_pred:log.val_acc}`);
      }
    }
  });

  await model.save(`file://${MODEL_DIR}`);
  console.log(`🎉 Modelo e scaler salvos em ${MODEL_DIR}`);
}

train().catch(err => {
  console.error('❌ Erro no treinamento:', err);
  process.exit(1);
});
