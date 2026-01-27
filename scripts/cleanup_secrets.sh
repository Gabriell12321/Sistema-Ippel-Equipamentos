#!/bin/sh
# Script de exemplo para remover arquivos sensíveis do histórico do Git.
# **Atenção**: Este script reescreve o histórico. Teste em um clone local e comunique a equipe.

set -e

echo "=== Este script mostrará comandos para usar com git-filter-repo / BFG. NÃO EXECUTA automaticamente ==="

echo "Com git-filter-repo (recomendado):"
echo "  git clone --mirror git@github.com:your/repo.git repo-mirror.git"
echo "  cd repo-mirror.git"
echo "  git filter-repo --invert-paths --paths ippel_system.db --paths ippel_secret.key"
echo "  git push --force"

echo "Com BFG (alternativa):"
echo "  java -jar bfg.jar --delete-files ippel_system.db --delete-files ippel_secret.key --no-blob-protection"
echo "  git reflog expire --expire=now --all && git gc --prune=now --aggressive"
echo "  git push --force"

echo "Depois de reescrever, rotacione segredos e atualize os environments/CI." 
