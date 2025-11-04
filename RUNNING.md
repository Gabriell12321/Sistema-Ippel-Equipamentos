# RUNNING.md — Como executar o projeto IPPEL localmente (dev)

Este arquivo resume passos rápidos para executar o sistema IPPEL localmente em um ambiente de desenvolvimento (Windows / PowerShell). Inclui variáveis de ambiente importantes, comandos PowerShell e dicas práticas.

## Pré-requisitos
- Python 3.10+ (recomendado) instalado e disponível no PATH
- Node 18+ (se for usar o serviço de e-mail em Node)
- Git
- Docker/Docker Compose (opcional para rodar via containers)

## Variáveis de ambiente relevantes
- `IPPEL_SECRET_KEY` — secret do Flask/Session (substitui value hardcoded se presente).
- `IPPEL_BACKUP_DIR` — diretório para backups do DB (opcional).
- `DATABASE_PATH` — caminho para o arquivo SQLite (padrão `ippel_system.db`).
- SMTP (para envio de e-mail; usadas por `server.js`/`server.py`):
  - `SMTP_HOST`
  - `SMTP_PORT`
  - `SMTP_USER`
  - `SMTP_PASS`
  - `SMTP_FROM` (opcional)

## Rodando em ambiente virtual (PowerShell)
1. Criar e ativar venv

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Instalar dependências (dev)

```powershell
pip install -r requirements.txt
# ou para um conjunto de produção mais enxuto:
pip install -r requirements_production.txt
```

3. Executar o servidor principal (admin)

# exemplo (PowerShell):
$env:IPPEL_SECRET_KEY = "sua_chave_secreta_aqui"
python main_system.py

Por padrão `main_system.py` inicia o app Flask + Flask-SocketIO (porta 5000 por padrão). Se houver certificados TLS/HTTPS no projeto, o código pode escolher HTTPS automaticamente.

4. Executar o servidor de formulários (opcional)

# se quiser rodar o `server_form.py` (app público/modular):
$env:IPPEL_SECRET_KEY = "sua_chave_secreta_aqui"
python server_form.py

5. Serviço de e-mail (Node) — opcional

```powershell
cd server_js_or_root_where_serverjs_is
npm install
$env:SMTP_HOST = "smtp.example.com"
$env:SMTP_PORT = "587"
$env:SMTP_USER = "user"
$env:SMTP_PASS = "pass"
node server.js
# ou: npm run start
```

Também existe uma versão Python `server.py` que implementa endpoint semelhante para envio de e-mail — escolha uma implementação em produção e desative/ignore a outra para reduzir ambiguidade.

6. Rodar via Docker Compose (opcional)

O repositório contém um `docker\docker-compose.yml` com serviços (ippel-app, redis, nginx, prometheus, grafana, backup). Para rodar:

```powershell
cd docker
docker compose up --build
```

7. Testes (pytest)

Com venv ativo e dependências instaladas:

```powershell
pytest -q
```

## Observações importantes
- O banco é SQLite (`ippel_system.db`) e o código usa PRAGMAs (WAL, busy_timeout) em vários pontos. Evite múltiplos processos escrevendo simultaneamente sem garantir locks/coordenação.
- Há referências a duas implementações de envio de e-mail (Node + Python). Recomenda-se padronizar para apenas uma em produção.
- Foram detectadas inconsistências de esquema (ex.: referências a `rncs` vs `rnc_reports`). Antes de mudanças de produção, executar um script de migração/dry-run e backup completo do DB.
- `main_system.py` contém um valor hardcoded de `app.secret_key` e um backup dir padrão. Recomenda-se fornecer esses valores via variáveis de ambiente (`IPPEL_SECRET_KEY`, `IPPEL_BACKUP_DIR`).

## Troubleshooting rápido
- Erro SQLite 'database is locked': aguarde e tente novamente; em dev você pode aumentar `busy_timeout` nas conexões.
- Porta em uso: verifique se outro processo está rodando (p.ex. outro server Python/Node). Use `Get-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess` no PowerShell para investigar.

## Próximos passos sugeridos
1. Rodar a suíte de testes (`pytest`) e corrigir falhas.
2. Gerar script de migração idempotente para reconciliar `rncs` vs `rnc_reports` e testar em DB de cópia.
3. Parametrizar segredos e documentar o processo de deploy (variáveis de ambiente + orquestração Docker).

---
Arquivo criado automaticamente pelo assistente para ajudar desenvolvimento local. Se quiser que eu execute os testes agora ou gere a migração, diga qual ação prefere.
