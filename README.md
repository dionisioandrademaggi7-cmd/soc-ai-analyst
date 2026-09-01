# SOC AI Analyst

Assistente de IA para triagem e investigação de alertas de segurança, pensado para um **lab purple team** (Ubuntu = alvo com o analista; Kali = peer de lab). A IA é **apoio à decisão**, não a decisão final: o humano fica no loop (human-in-the-loop) para escalonar, validar logons e **confirmar** qualquer bloqueio ufw live.

Nunca commitar o `.env` (já deve estar no `.gitignore`). Tokens e chaves são segredo.

---

## Arquitetura

```
config.py             → carrega .env e valida configuração (Splunk + Groq)
splunk_client.py      → busca alertas e eventos de contexto na API REST do Splunk
local_log_client.py   → lê auth.log localmente, mesma interface do SplunkClient
mock_splunk_client.py → dados simulados para desenvolvimento sem Splunk/logs reais
windows_log_client.py → Event Log de Segurança do Windows (4625 falha / 4624 sucesso)
ai_analyst.py         → prompts e chamadas ao Groq (triagem + investigação)
report_generator.py   → monta os relatórios em markdown
main.py               → CLI (fase 1; também contain / watch)
app.py                → interface web em Streamlit (fase 2; ainda no repositório)
containment.py        → bloqueio/desbloqueio de IP via ufw (dry-run por omissão)
session_watch.py      → sessões SSH ativas vs whitelist
geo.py                → geolocalização de IPs (ip-api) para o mapa
sec_tools.py          → snapshot de defesa do host
alerter.py            → motor de alerta autónomo (BURST / LOGIN)
watcher.py            → CLI do alerter (sem API)
api.py                → FastAPI + UI (fase 4)
frontend/             → dashboard (index.html, app.js, styles.css)
```

A lógica de negócio (clientes, `AIAnalyst`, relatórios, containment) fica isolada da CLI/UI — a API e o Streamlit reutilizam as mesmas classes.

---

## Instalação

```bash
cd soc-ai-analyst
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edite o .env: GROQ_API_KEY, e (opcional) host/token do Splunk
```

### Obtendo o token do Splunk

No Splunk: **Settings → Tokens → New Token**. Se a autenticação por token não estiver
habilitada, um admin precisa ativá-la em Settings → Tokens → Token Authentication.

### Ajustando a query de alertas

A variável `SPLUNK_ALERT_QUERY` no `.env` define quais eventos contam como "alertas".
- Se você usa **Splunk Enterprise Security**: `search index=notable status=unassigned`
- Sem ES, com alertas salvos indexando em algum sourcetype próprio: ajuste para o seu caso,
  ex: `search index=main sourcetype=alert_ids`

---

## Fase 1 — CLI

Validar a lógica via linha de comando (Splunk, mock ou logs locais) antes de expor como aplicação web.

### Fontes de dados

| Fonte | Quando usar | Flag (CLI) |
|---|---|---|
| Mock | Desenvolver sem depender de nada externo | `--mock` |
| Logs locais | Testar contra `auth.log` da máquina | `--local` |
| Windows Event Log | Host Windows (4625 / 4624) | `--windows` |
| Splunk | Ambiente com Splunk configurado | padrão |

### Triagem em lote

Busca os alertas pendentes e classifica cada um (severidade, categoria, se é falso
positivo, ações recomendadas):

```bash
python main.py triage --count 20
python main.py triage --local --count 10
python main.py triage --mock --count 5
```

Gera um arquivo em `reports/triage_<timestamp>.md` com uma tabela-resumo ordenada por
severidade e o detalhamento de cada alerta.

Campos extra na triagem (além da fase 1 original):
- `attack_stage` — fase provável do ataque (ex: "Initial Access", "Lateral Movement")
- `containment_actions` — ações defensivas imediatas (bloquear IP, isolar host, etc.)
- `priority_score` — pontuação de 1 a 100 pra ordenar urgência

### Investigação de incidente

Dado um host e/ou usuário, busca eventos correlacionados numa janela de tempo e pede ao
Groq uma análise aprofundada (timeline, causa raiz, blast radius, contenção):

```bash
python main.py investigate --host 10.0.0.5 --user jdoe --earliest -2h --latest +1h
python main.py investigate --local --host ubuntu-lab
```

Gera `reports/investigation_<timestamp>.md`.

---

## Fase 2 — Interface Web (Streamlit)

A fase 2 reaproveitou a lógica da fase 1 sem reescrever nada — só ganhou uma camada
de interface web (`app.py`, Streamlit) e a fonte de logs locais. **`app.py` continua
no repositório**; a UI principal do lab passou a ser a FastAPI (fase 4), mas o
Streamlit não foi removido.

```bash
streamlit run app.py
```

Abre em `http://localhost:8501`.

- **Threat Map** — plota geograficamente os IPs de origem identificados nos alertas
  triados (geolocalização via `ip-api.com`).
- **Aba Triagem** — triagem em lote: diagnóstico principal, métricas, ações recomendadas.
- **Aba Investigação** — contexto por host/usuário e relatório aprofundado na tela.

A camada de IA (`ai_analyst.py`) usa a **API do Groq** (modelo por omissão
`llama-3.3-70b-versatile`). A chave fica em `GROQ_API_KEY` no `.env`.

---

## Fase 3 — Containment (ufw, dry-run / whitelist)

Ações defensivas **locais** no Ubuntu do lab: bloquear/desbloquear IP via `ufw`.
**Dry-run por omissão.** Bloqueio live só com `--execute` (CLI) ou o botão
«Executar block» no dashboard — sempre com humano a confirmar.

```bash
python main.py contain --block 203.0.113.10            # dry-run
python main.py contain --block 203.0.113.10 --execute  # live (humano no loop)
python main.py contain --unblock 203.0.113.10
python main.py contain --status
python main.py watch                                   # sessões SSH vs whitelist
python main.py watch --block                           # contain dry-run se sessão estrangeira
python main.py watch --block --execute                 # contain live (humano no loop)
```

Whitelist (nunca bloquear): `127.0.0.1`, `::1`, e no lab NAT **`10.0.2.2` / `10.0.2.15`**.
O `containment.py` recusa esses IPs mesmo com `--execute`.

---

## Fase 4 — FastAPI UI

Dashboard no browser (Leaflet/OSM), triagem/investigação via API, sessões SSH,
containment e o **alerta autónomo** (faixa no topo).

```bash
uvicorn api:app --host 127.0.0.1 --port 8000
```

Abre em `http://127.0.0.1:8000`. **Dashboard no ar = watcher autónomo a correr**
(o startup da API chama `alerter.start_background`; não há botão para “começar a vigiar”).

Endpoints úteis:
- `GET /api/health`
- `GET /api/alerts/live` — anel em memória (BURST / LOGIN) + `running` / fonte / limiar
- `POST /api/triage` / `POST /api/investigate`
- `GET /api/sessions` — sessões SSH e as que estão fora da whitelist
- `POST /api/watch` — um ciclo de session watch
- `POST /api/contain` — `{ ip, action: block|unblock, execute: false }`
- `GET /api/defense` — snapshot ufw / fail2ban + último mapa
- `GET /api/auth-live` — últimas linhas parseadas do `auth.log`

O mapa usa tiles OpenStreetMap e geolocalização via `ip-api` (`geo.py`).
Fonte no UI: logs locais, mock ou Windows Event Log (`windows_log_client.py`).

---

## Alerta autónomo (`alerter.py`)

O `watcher.py` antigo só imprimia linhas novas se o operador o lançasse à mão,
Agora **cada evento novo** dispara sozinho (som + banner + faixa no UI), sem clicar em Triagem. BURST é só o extra da rajada.

| Tipo | Quando dispara |
|---|---|
| **FAIL / INVALID** | **cada** falha ou user inválido novo (não espera pela 5ª) |
| **LOGIN** | cada `Accepted password` / `Accepted publickey` (ou Windows 4624) fora da whitelist |
| **SUDO / SESSION / SSH** | sudo, sessão aberta/fechada, outras linhas sshd |
| **BURST** | extra: 5 falhas do mesmo IP em 120s |

O alerta soa sozinho (`notify-send` + BEL no Linux; Beep/balloon no Windows) e
instruí a abrir **Triagem / Investigar** no SOC AI Analyst para o relatório
detalhado. Containment **não** corre sozinho com o dashboard: o alerter da API
arranca com `auto_block=False`. Bloqueio ufw live só com:

```bash
python watcher.py --block --execute
```

ou o botão **«Executar block»** no UI (confirmação humana).

Linhas históricas (já no log quando o tail começa) **só alimentam a janela de
falhas** — não disparam som. Há cooldown por IP+tipo (~60s) para não spammar BURST.
Um LOGIN depois de um BURST no mesmo IP **é permitido** (tipo diferente).

Linux: `auth.log` / `secure` / `journalctl -u ssh`. Windows (sem esses logs):
Event Log 4625 (falha) e 4624 (sucesso) via `WindowsLogClient`.

### API vs CLI watcher

```bash
# suficiente para alertas autónomos (dashboard + watcher em background)
uvicorn api:app --host 127.0.0.1 --port 8000

# só CLI (sem API / sem UI)
python watcher.py

# contain em dry-run após BURST/LOGIN
python watcher.py --block

# ufw deny a sério (human-in-the-loop)
python watcher.py --block --execute
```

No UI, **Executar block** continua a ser o caminho live. O alerter da API
não bloqueia sozinho — o som dispara, o block ufw não.

### Variáveis de ambiente (opcional)

| env | default | significado |
|---|---|---|
| `SOC_FAIL_THRESHOLD` | 5 | falhas por IP para BURST |
| `SOC_WINDOW_SEC` | 120 | janela deslizante (segundos) |
| `SOC_COOLDOWN_SEC` | 60 | silêncio após alerta (por IP+tipo) |

---

## Testes

Os testes do alerter são **defensivos**: alimentam linhas sintéticas de `auth.log`
em `alerter.handle_line` / `_handle_parsed`. Não abrem sockets, não fazem SSH,
não chamam `ufw` de verdade (`containment.block_ip` é stub quando o teste toca
em `auto_block`).

`pytest` **não** está em `requirements.txt`. O ficheiro é `unittest` da stdlib:

```bash
python -m unittest tests.test_alerter -q
```

Se tiver pytest instalado no ambiente:

```bash
python -m pytest tests/test_alerter.py -q
```

---

## Validação no lab (alto nível)

Ambiente purple team já existente: **Ubuntu = alvo** (corre o analista);
**Kali = peer de lab** que gera falhas de autenticação SSH / um logon bem-sucedido
contra esse host, **do modo como o lab já faz** — sem procedimentos de ataque
neste README.

No Ubuntu (alvo / analista):

1. `uvicorn api:app --host 127.0.0.1 --port 8000`
2. Confirmar `GET /api/alerts/live` com `"running": true`
3. Correr `python -m pytest tests/test_alerter.py -q` (ou o `unittest` acima)
4. No lab, produzir falhas de autenticação SSH a partir do Kali e, depois, um
   logon bem-sucedido a partir desse host
5. Confirmar **BURST** e depois **LOGIN** na faixa «Alerta autónomo» do dashboard
6. Contain em dry-run (Simular block / `python main.py contain --block <IP>`)
7. Humano confirma o block live («Executar block» ou `--execute`)

Whitelist `10.0.2.2` / `10.0.2.15` não deve ser bloqueada mesmo em live.

---

## Notas de segurança

- Nunca commitar o `.env`.
- `GROQ_API_KEY` e o token do Splunk dão acesso a dados sensíveis — trate como
  segredo (idealmente um vault/secrets manager se isto sair do lab).
- Containment chama `sudo ufw` — o operador precisa de sudo no Ubuntu do lab;
  dry-run é o default; live exige confirmação humana.
- Whitelist: `127.0.0.1` / `::1` nunca geram alerta LOGIN/BURST (session watch);
  `10.0.2.2` / `10.0.2.15` nunca são bloqueados (lab NAT).
- O mapa consulta `ip-api.com` (e, no Streamlit, a GUI também pode consultar a
  localização pública via `ipify`/`ip-api.com`) — isso envia IPs a um serviço
  terceiro.
- As respostas da IA são um **apoio à triagem, não uma decisão final** — o
  `escalate: true` e o campo `false_positive_likelihood` existem justamente para
  manter um humano no loop nos casos de maior risco. O alerta autónomo manda
  abrir Triagem/Investigar; não bloqueia sozinho.

---

## Changelog (resumo)

### [Não lançado] — Alerta autónomo + FastAPI (fases 3–4)
- `alerter.py`: BURST (5 falhas / 120s) e LOGIN fora da whitelist; som + faixa no UI
- Dashboard FastAPI (`api.py` + `frontend/`); mapa OSM; session watch; Windows Event Log
- Containment ufw com dry-run / whitelist; block live só com humano
- Testes sintéticos em `tests/test_alerter.py`

### Fase 2 — Interface Web (Streamlit)
- `app.py` (ainda no GitHub) com tema visual próprio
- Mapa de ameaças; migração da IA de Gemini para Groq (Llama 3.3 70B)
- Novos campos na triagem: `attack_stage`, `containment_actions`, `priority_score`

### v0.2.0 — Fonte de dados local
- `local_log_client.py` + flag `--local`

### v0.1.0 — Versão inicial (Fase 1)
- Triagem e investigação via Splunk ou dados mock
