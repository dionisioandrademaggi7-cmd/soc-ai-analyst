# SOC AI Analyst (Fase 1 — CLI Linux)

Assistente de IA para triagem e investigação de alertas de segurança, integrado ao Splunk.
Esta é a fase 1: validar a lógica via linha de comando antes de expor como aplicação web.

## Arquitetura

```
config.py           → carrega .env e valida configuração
splunk_client.py     → busca alertas e eventos de contexto na API REST do Splunk
ai_analyst.py        → prompts e chamadas ao Gemini (triagem + investigação)
report_generator.py  → monta os relatórios em markdown
main.py               → CLI que orquestra tudo
```

Esses módulos foram escritos para não conhecer nada de CLI/terminal — toda a lógica de
negócio fica isolada, então na fase 2 dá pra importar exatamente as mesmas classes
(`SplunkClient`, `AIAnalyst`, `report_generator`) dentro de uma API FastAPI/Flask sem
reescrever nada.

## Instalação

```bash
cd soc_ai_analyst
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edite o .env com host/token do Splunk e sua chave da API Gemini
```

### Obtendo o token do Splunk

No Splunk: **Settings → Tokens → New Token**. Se a autenticação por token não estiver
habilitada, um admin precisa ativá-la em Settings → Tokens → Token Authentication.

### Ajustando a query de alertas

A variável `SPLUNK_ALERT_QUERY` no `.env` define quais eventos contam como "alertas".
- Se você usa **Splunk Enterprise Security**: `search index=notable status=unassigned`
- Sem ES, com alertas salvos indexando em algum sourcetype próprio: ajuste para o seu caso,
  ex: `search index=main sourcetype=alert_ids`

## Uso

### Triagem em lote
Busca os alertas pendentes e classifica cada um (severidade, categoria, se é falso
positivo, ações recomendadas):

```bash
python main.py triage --count 20
```

Gera um arquivo em `reports/triage_<timestamp>.md` com uma tabela-resumo ordenada por
severidade e o detalhamento de cada alerta.

### Investigação de incidente
Dado um host e/ou usuário, busca eventos correlacionados numa janela de tempo e pede ao
Gemini uma análise aprofundada (timeline, causa raiz, blast radius, contenção):

```bash
python main.py investigate --host 10.0.0.5 --user jdoe --earliest -2h --latest +1h
```

Gera `reports/investigation_<timestamp>.md`.

## Próximos passos (fase 2 — web)

- Envolver `SplunkClient` + `AIAnalyst` + `report_generator` numa API (FastAPI é uma boa
  escolha: endpoints assíncronos, fácil gerar OpenAPI para o frontend).
- Endpoints sugeridos: `POST /triage`, `POST /investigate`, `GET /reports/{id}`.
- Fila de background (ex: RQ/Celery) para não bloquear a UI enquanto o Gemini processa
  lotes grandes de alertas.
- Autenticação/RBAC antes de expor para a equipe.

## Notas de segurança

- Nunca commitar o `.env` (já deve estar num `.gitignore`).
- O token do Splunk e a API key do Gemini dão acesso a dados sensíveis — trate como
  segredo (idealmente um vault/secrets manager na fase web).
- As respostas da IA são um apoio à triagem, não uma decisão final — o `escalate: true`
  e o campo `false_positive_likelihood` existem justamente para manter um humano no loop
  nos casos de maior risco.

---

# Fase 2 — Interface Web (Streamlit)

A fase 2 chegou: a lógica de negócio da fase 1 (`ai_analyst.py`, `report_generator.py`)
foi reaproveitada sem reescrever nada, exatamente como planejado — só ganhou uma camada
de interface web em cima (`app.py`, Streamlit) e novas fontes de dados.

## Novidades

### Nova fonte de dados: logs locais
Além do Splunk e do mock, agora dá pra rodar **sem Splunk nenhum**, lendo direto do
`auth.log` da máquina — útil pra testar contra ataques reais (ex: força bruta SSH via
Kali/Hydra) sem precisar montar um Splunk completo.

```
local_log_client.py → lê /var/log/auth.log, mesma interface do SplunkClient
```

Fontes de dados disponíveis agora:

| Fonte | Quando usar | Flag/opção |
|---|---|---|
| Mock | Desenvolver sem depender de nada externo | `--mock` (CLI) / "Mock" (GUI) |
| Logs locais | Testar contra `auth.log` real da máquina | `--local` (CLI) / "Logs locais" (GUI) |
| Splunk | Ambiente com Splunk configurado | padrão (CLI) / "Splunk" (GUI) |

### Migração de Gemini para Groq
A camada de IA (`ai_analyst.py`) migrou do Gemini para a **API do Groq** (modelo
`llama-3.3-70b-versatile`) — resolve problemas de autenticação persistentes que o
Gemini estava apresentando (chaves no formato `AQ.` retornando erro
`ACCESS_TOKEN_TYPE_UNSUPPORTED`). A API key agora fica em `GROQ_API_KEY` no `.env`
(no lugar de `GEMINI_API_KEY`).

Novos campos na triagem, além dos da fase 1:
- `attack_stage` — fase provável do ataque (ex: "Initial Access", "Lateral Movement")
- `containment_actions` — ações defensivas imediatas (bloquear IP, isolar host, etc.)
- `priority_score` — pontuação de 1 a 100 pra ordenar urgência

### Interface web (`app.py`)
```bash
streamlit run app.py
```
Abre em `http://localhost:8501`.

- **Threat Map** — plota geograficamente os IPs de origem identificados nos alertas
  triados (geolocalização via `ip-api.com`), com sua própria localização como base.
- **Aba Triagem** — roda a triagem em lote com um clique: diagnóstico principal (pior
  severidade), métricas (alertas, escalonados, IPs no mapa), e cada alerta classificado
  com ações recomendadas e de contenção.
- **Aba Investigação** — busca contexto por host/usuário e gera o relatório aprofundado
  direto na tela.

## Arquitetura atualizada

```
config.py            → carrega .env e valida configuração (Splunk + Groq)
splunk_client.py      → busca alertas e eventos de contexto na API REST do Splunk
local_log_client.py   → lê auth.log localmente, mesma interface do SplunkClient
mock_splunk_client.py → dados simulados para desenvolvimento sem Splunk/logs reais
ai_analyst.py         → prompts e chamadas ao Groq (triagem + investigação)
report_generator.py   → monta os relatórios em markdown
main.py               → CLI (fase 1)
app.py                → interface web em Streamlit (fase 2)
```

## Changelog

### [Não lançado] — Fase 2: Interface Web
- Nova interface em Streamlit (`app.py`) com tema visual próprio (dark/cyberpunk)
- Mapa de ameaças com geolocalização dos IPs de origem
- Migração da IA de Gemini para Groq (Llama 3.3 70B)
- Novos campos na triagem: `attack_stage`, `containment_actions`, `priority_score`
- Abas separadas para Triagem e Investigação na GUI

### v0.2.0 — Fonte de dados local
- Adicionado `local_log_client.py`: permite rodar sem Splunk, lendo direto de
  `/var/log/auth.log`
- Nova flag `--local` em `triage` e `investigate`
- Avisos explícitos quando o log não existe ou falta permissão de leitura

### v0.1.0 — Versão inicial (Fase 1)
- Triagem e investigação via Splunk ou dados mock
- Integração inicial com IA (Gemini) para análise de alertas

## Próximos passos (atualizado)

- Corrigir renderização de acentuação nos expanders da GUI (verificar encoding)
- Autenticação/RBAC antes de expor a equipe
- Fila de background (RQ/Celery) para lotes grandes de alertas sem travar a UI
- Testes automatizados para `ai_analyst.py` (parsing de resposta, fallback)

## Notas de segurança (atualizado)

- A GUI consulta sua própria localização pública (via `ipify`/`ip-api.com`) para
  plotar a "base" no mapa — isso envia seu IP público a um serviço terceiro a cada
  carregamento da página.
