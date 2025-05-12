# PF de Tech Hack - Sérgio Carmelo

**SSS Phish Detector** é uma ferramenta web completa para **detecção de phishing**, combinando **verificações heurísticas avançadas**, integração com **listas de domínios maliciosos** e um **modelo de Machine Learning** treinado para avaliar o risco de qualquer URL.

---

## Descrição

Com interface intuitiva e API RESTful, o SSS Phish Detector permite ao usuário:
- **Inserir URLs** ou navegar com nossa interface web responsiva.  
- Verificar em tempo real se o domínio aparece em listas de phishing conhecidas.  
- Analisar **características técnicas** (idade do domínio, SSL, typosquatting, DNS dinâmico).  
- Obter um **score de risco** quantitativo (0–100) e explicações claras de cada fator que contribuiu à classificação.  
- Visualizar um **dashboard analítico** com detalhes da predição do modelo de ML e heurísticas.

O projeto atende aos requisitos acadêmicos de **Conceito C, B e A** (Opção 3 – Ferramenta para detecção de Phishing) e vai além ao integrar aprendizado de máquina e um front-end profissional.

---

## Funcionalidades

### Conceito C (Nota C)
- **Verificação em listas** de phishing (PhishTank, OpenPhish, lista própria).  
- **Detecção básica** de domínios suspeitos:
  - Números substituindo letras  
  - Uso excessivo de subdomínios  
  - Caracteres especiais na URL  
- **Interface web simples** com resultado verde/vermelho.

### Conceito B (Nota B)
- **Heurísticas avançadas**:
  - Idade do domínio (WHOIS)  
  - Validação de certificado SSL (emissor, expiração)  
  - Detecção de typosquatting (distância de Levenshtein)  
- **Dashboard interativo**:
  - Histórico de verificações  
  - Tabelas e explicações de cada heurística  
  - Exportação de resultados  

### Conceito A (Nota A)
- **Sistema web avançado** com **Machine Learning**:
  - **7 features** no modelo:
    1. Comprimento da URL  
    2. Número de subdomínios  
    3. Caracteres especiais  
    4. Contagem de palavras-chave suspeitas  
    5. País de hospedagem (GeoIP)  
    6. Typosquatting  
    7. Presença na lista de phishing  
  - **Normalização Min–Max** e rede neural pré-treinada (TensorFlow.js).  
  - **ML risk** (probabilidade bruta e risco %), combinado 60/40 com heurísticas.  
- **Análise de conteúdo básica**:
  - Verificação de formulários de login  
  - Deteção de parâmetros OAuth suspeitos  
- **Relatório explicável** com todos os fatores que influenciaram a decisão.

---

##  Pré-requisitos

- **Node.js** ≥ 12  
- **npm** ou **yarn**  
- (Opcional) Chave **AbuseIPDB** se quiser ativar reputação de IP

---

##  Instalação

1. **Clone** este repositório  
   ```bash
   git clone https://github.com/seu-usuario/sss-phish-detector.git
   cd sss-phish-detector
```

2. **Instale** as dependências

   ```bash
   npm install
   ```

3. **Gere** a lista de domínios legítimos

   ```bash
   node scripts/genLegitList.js
   ```

   Este script baixa e salva em `data/legitList.json` os top 10 000 domínios.

4. **Treine** o modelo de ML

   ```bash
   node scripts/trainModel.js
   ```

   * cria `model/scaler.json` e `model/model.json`
   * undersampling automática de phishing vs. legítimos

5. **Configure** variáveis de ambiente (opcional)

   ```bash
   # exemplo .env
   ABUSEIPDB_API_KEY=suachaveaqui
   ```

---

##  Uso

1. **Inicie** o servidor

   ```bash
   node server.js
   ```

2. **Abra** no navegador

   ```
   http://localhost:3000
   ```

3. **Teste** via API

   ```bash
   curl "http://localhost:3000/check?url=https://www.example.com"
   ```

   → Resposta JSON com:

   * `riskScore` (0–100)
   * `heuristics` detalhadas
   * `ml.mlProb` e `ml.mlRisk`
   * `explanation` (fatores contributivos)

---

##  Estrutura de Diretórios

```
.
├── data/
│   ├── phishingList.json    # domínios maliciosos
│   └── legitList.json       # domínios legítimos (gerado)
├── model/
│   ├── model.json           # modelo TF.js
│   └── scaler.json          # parâmetros de normalização
├── public/                  # front-end estático (HTML/CSS/JS)
├── scripts/
│   ├── genLegitList.js      # gera legitList.json
│   └── trainModel.js        # treina e salva o modelo
├── server.js                # API e heurísticas
├── .gitignore
└── README.md
```


---

##  Licença

Este projeto está sob a **MIT License**. 
