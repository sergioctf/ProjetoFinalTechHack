document.addEventListener('DOMContentLoaded', () => {
  const urlInput        = document.getElementById('urlInput');
  const checkButton     = document.getElementById('checkButton');
  const resultSection   = document.getElementById('resultSection');
  const riskLabel       = document.getElementById('riskLabel');
  const riskScoreEl     = document.getElementById('riskScore');
  const heuristicsList  = document.getElementById('heuristicsList');
  const explanationList = document.getElementById('explanationList');
  const riskExplanation = document.getElementById('riskExplanation');

  // Mapeamento de labels para heurísticas
  const labelMap = {
    inList: 'Na lista de phishing',
    ageDays: 'Idade do domínio (dias)',
    sslValid: 'SSL válido',
    sslDaysRemaining: 'Dias até expirar SSL',
    minLevenshtein: 'Typosquatting (LEV)'
  };

  // Formatação de valores nulos/booleanos
  function fmt(val) {
    if (val === null) return 'Desconhecido';
    if (typeof val === 'boolean') return val ? 'Sim' : 'Não';
    return val;
  }

  checkButton.addEventListener('click', async () => {
    // 1) Captura e normaliza a URL
    let raw = urlInput.value.trim();
    if (!raw) {
      return alert('Cole uma URL para iniciar a verificação.');
    }
    // Se faltar protocolo, adiciona http://
    if (!/^https?:\/\//i.test(raw)) {
      raw = 'http://' + raw;
    }

    // 2) Limpa resultados anteriores
    heuristicsList.innerHTML  = '';
    explanationList.innerHTML = '';
    riskExplanation.innerHTML = '';
    resultSection.hidden      = true;

    try {
      // 3) Chama a API
      const res  = await fetch(`http://localhost:3000/check?url=${encodeURIComponent(raw)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Erro ao verificar');

      // 4) Define cor e texto do nível de risco
      let cls, text;
      if (data.isPhishing || data.riskScore >= 70) {
        cls  = 'risk-high';
        text = 'Alto';
      } else if (data.riskScore >= 30) {
        cls  = 'risk-medium';
        text = 'Médio';
      } else {
        cls  = 'risk-low';
        text = 'Baixo';
      }
      riskLabel.textContent   = text;
      riskLabel.className     = `risk-label ${cls}`;
      riskScoreEl.textContent = data.riskScore;

      // 5) Mensagem de explicação geral
      if (data.riskScore >= 70) {
        riskExplanation.innerHTML = `
          <div class="risk-explanation risk-high-box">
            <strong>Alto risco de phishing:</strong> Vários sinais críticos foram detectados. Cuidado máximo!
          </div>`;
      } else if (data.riskScore >= 30) {
        riskExplanation.innerHTML = `
          <div class="risk-explanation risk-medium-box">
            <strong>Risco médio:</strong> Alguns alertas foram disparados. Revise antes de prosseguir.
          </div>`;
      } else {
        riskExplanation.innerHTML = `
          <div class="risk-explanation risk-low-box">
            <strong>Baixo risco:</strong> Sem evidências críticas. Ainda assim, valide o contexto.
          </div>`;
      }

      // 6) Popula lista de heurísticas
      Object.entries(data.heuristics).forEach(([key, val]) => {
        const li = document.createElement('li');
        li.className = `heuristic-item ${
          val === null ? 'null' : val ? 'true' : 'false'
        }`;
        li.innerHTML = `
          <span class="heuristic-label">${labelMap[key] || key}</span>
          <span class="heuristic-value">${fmt(val)}</span>
        `;
        heuristicsList.appendChild(li);
      });

      // 7) Popula observações (explicações detalhadas)
      if (data.explanation && data.explanation.length) {
        data.explanation.forEach(msg => {
          const li = document.createElement('li');
          li.textContent = msg;
          explanationList.appendChild(li);
        });
      } else {
        const li = document.createElement('li');
        li.textContent = 'Nenhuma evidência crítica encontrada.';
        explanationList.appendChild(li);
      }

      // 8) Detalhes do ML
      const mlSection = document.createElement('div');
      mlSection.className = 'subsection';
      mlSection.innerHTML = `
        <h3>Detalhes do Modelo de ML</h3>
        <table class="ml-table">
          <tr><th>Característica</th><th>Valor</th></tr>
          ${Object.entries(data.ml.mlFeatures).map(([k,v]) =>
            `<tr><td>${k}</td><td>${v}</td></tr>`
          ).join('')}
          <tr><td><strong>Probabilidade bruta</strong></td>
              <td>${(data.ml.mlProb*100).toFixed(2)}%</td></tr>
          <tr><td><strong>Risco ML</strong></td>
              <td>${data.ml.mlRisk}%</td></tr>
        </table>
      `;
      resultSection.appendChild(mlSection);

      // 8) Exibe o card de resultado
      resultSection.hidden = false;
    } catch (err) {
      alert(`⚠️ ${err.message}`);
    }
  });
});
