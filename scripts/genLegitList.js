// scripts/genLegitList.js
const axios = require('axios');
const AdmZip = require('adm-zip');
const fs    = require('fs');
const path  = require('path');

async function genLegit() {
  console.log('🔄 Baixando ZIP top-1m do Cisco Umbrella…');
  const zipUrl = 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip';

  let res;
  try {
    // responseType arraybuffer para ler binário
    res = await axios.get(zipUrl, { responseType: 'arraybuffer' });
  } catch (err) {
    console.error('❌ Falha ao baixar ZIP:', err.message);
    process.exit(1);
  }

  console.log('📄 Descompactando ZIP…');
  const zip = new AdmZip(res.data);
  // busca a entrada CSV dentro do ZIP
  const entry = zip.getEntries().find(e => e.entryName.endsWith('.csv'));
  if (!entry) {
    console.error('❌ CSV não encontrado no ZIP');
    process.exit(1);
  }

  const csv = entry.getData().toString('utf-8');
  console.log('📄 Processando CSV…');
  const lines = csv.split('\n');
  // pega as 10k primeiras linhas (sem header, se houver)
  const domains = lines
    .slice(1, 10001)              // pula header e pega 10.000
    .map(l => l.split(',')[1])    // coluna domínio
    .filter(Boolean);

  // escreve JSON
  const outPath = path.join(__dirname, '../data/legitList.json');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(domains, null, 2), 'utf-8');

  console.log(`✅ Gravado ${domains.length} domínios legítimos em data/legitList.json`);
}

genLegit().catch(err => {
  console.error('❌ Erro inesperado:', err);
  process.exit(1);
});
