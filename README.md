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