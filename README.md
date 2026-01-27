# IPPEL RNC System

Repositório do sistema de Relatórios de Não-Conformidade (RNC) da IPPEL.

## Objetivo
Breve documentação de setup, segurança e como contribuir para o projeto.

---

## Instalação (local)

Requisitos:
- Python 3.11+
- Node.js (para ferramentas frontend se necessário)

1. Crie um ambiente virtual:

```bash
python -m venv .venv
source .venv/bin/activate  # ou .\.venv\Scripts\activate no Windows
pip install -r data/requirements.txt
```

2. Configurar variáveis de ambiente essenciais:

- `IPPEL_SECRET_KEY` — chave secreta do Flask (não commitar)
- `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` — credenciais de e-mail (opcionais para envio real)
- `DATABASE_PATH` — caminho do banco (opcional, por padrão usa `ippel_system.db` local)

Dica: coloque variáveis sensíveis em um arquivo `.env` (não comitado) ou configure via secrets do CI.

3. Para rodar localmente:

```bash
export FLASK_APP=server_form.py
flask run
```

---

## Segurança e segredos

- **NUNCA** comite segredos (chaves privadas, senhas, arquivos `.db`, certificados).
- O projeto possui `.gitignore` atualizando para evitar o commit de `*.db` e `ippel_secret.key`.
- Se você já comitou segredos, siga o passo "Removendo segredos do histórico" abaixo.

### Criar secret local (recomendado)
Crie um diretório `instance/` fora do código fonte versionado (já adicionado ao README) e coloque o arquivo `ippel_secret.key` com a chave. Alternativamente, use a variável de ambiente `IPPEL_SECRET_KEY`.

### Removendo segredos do histórico (avançado)
Este passo reescreve o histórico do Git e afeta todos os colaboradores. **Tenha certeza e comunique sua equipe antes de prosseguir**.

Exemplo (usando `git filter-repo`):

```bash
# Instale git-filter-repo (recomendado) e faça um backup
pip install git-filter-repo
git clone --mirror git@github.com:your/repo.git repo-mirror.git
cd repo-mirror.git
# Remover arquivos sensíveis por caminho e por padrão
git filter-repo --invert-paths --paths ippel_system.db --paths ippel_secret.key
# Faça push back para o remoto (FORÇADO)
git push --force
```

Outra opção: [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) — veja `scripts/cleanup_secrets.sh` para exemplos.

---

## CI: Pré-commit e varredura de segredos
- O repositório inclui `.pre-commit-config.yaml` (detect-secrets) e um workflow `secret-scan.yml` para varredura em pushes/PRs.

---

## Testes
- Use `pytest tests/` para executar os testes. Testes usam variáveis de ambiente para credenciais de teste (veja `tests/test_config.py`).

---

## Contribuição
1. Abra uma issue descrevendo o que deseja mudar.
2. Faça um fork e crie uma branch com seu trabalho.
3. Adicione testes quando aplicável.
4. Abra um PR e aguarde revisão.

Obrigado!
