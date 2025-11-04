"""
Teste de criação de RNC com CAUSADOR ESPECÍFICO
Simula criar RNC para Engenharia com Matheus Tocantins como causador
"""
import sqlite3
from datetime import datetime

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

print("="*80)
print("TESTE: CRIAÇÃO DE RNC COM CAUSADOR ESPECÍFICO")
print("="*80)

# Configuração do teste
CRIADOR_ID = 1  # Alan (admin)
GRUPO_ENGENHARIA_ID = 7
CAUSADOR_ID = 153  # Matheus Tocantins
GERENTE_ID = 14  # Guilherme
SUB_GERENTE_ID = 13  # Cintia
RONALDO_ID = 11  # Valorista

print(f"\n📋 Configuração do Teste:")
print(f"  - Criador: Alan (ID: {CRIADOR_ID})")
print(f"  - Grupo: Engenharia (ID: {GRUPO_ENGENHARIA_ID})")
print(f"  - Causador: Matheus Tocantins (ID: {CAUSADOR_ID})")
print(f"  - Gerente: Guilherme (ID: {GERENTE_ID})")
print(f"  - Sub-Gerente: Cintia (ID: {SUB_GERENTE_ID})")
print(f"  - Valorista: Ronaldo (ID: {RONALDO_ID})")

# Contar RNCs atuais
cursor.execute('SELECT MAX(CAST(rnc_number AS INTEGER)) FROM rncs')
last_rnc = cursor.fetchone()[0]
new_rnc_number = (last_rnc or 34000) + 1

print(f"\n📌 Próximo número RNC: {new_rnc_number}")

# SIMULAR o que o código faz quando recebe:
# - area_responsavel: "Engenharia"
# - causador_user_id: 153 (Matheus Tocantins)

print(f"\n" + "-"*80)
print("SIMULANDO LÓGICA DO BACKEND (routes/rnc.py)")
print("-"*80)

causador_user_id = CAUSADOR_ID
assigned_group_id = GRUPO_ENGENHARIA_ID
has_area_responsavel = True

# LÓGICA DO CÓDIGO ATUAL (linhas 454-464)
assign_to_all_group = False  # Default

if causador_user_id:
    # Nome Causador preenchido → Atribuir apenas para o causador + gerentes
    assign_to_all_group = False
    print(f"✓ Nome Causador preenchido (ID: {causador_user_id})")
    print(f"  → assign_to_all_group = False")
    print(f"  → Deveria atribuir para: Causador + Gerentes + Ronaldo")
elif has_area_responsavel:
    # Nome Causador vazio E setor selecionado → Atribuir para todo o grupo
    assign_to_all_group = True
    print(f"✓ Nome Causador vazio E setor selecionado")
    print(f"  → assign_to_all_group = True")
    print(f"  → Deveria atribuir para: TODO O GRUPO")

print(f"\n📊 Resultado da decisão:")
print(f"  assign_to_all_group = {assign_to_all_group}")

# VERIFICAR QUAL BLOCO VAI EXECUTAR
print(f"\n" + "-"*80)
print("VERIFICANDO QUAL BLOCO DE CÓDIGO VAI EXECUTAR")
print("-"*80)

# Primeira condição (linha 467): if assign_to_all_group and assigned_group_id and (...)
condicao1 = assign_to_all_group and assigned_group_id
print(f"\n1️⃣ Bloco MODO 1 (TODO O GRUPO):")
print(f"  Condição: assign_to_all_group={assign_to_all_group} AND assigned_group_id={assigned_group_id}")
print(f"  Resultado: {condicao1}")
if condicao1:
    print(f"  ✓ VAI EXECUTAR ESTE BLOCO")
    print(f"  → Vai compartilhar com TODOS os usuários do grupo")
else:
    print(f"  ✗ NÃO VAI EXECUTAR ESTE BLOCO")

# Segunda condição (linha 496): elif causador_user_id and assigned_group_id
condicao2 = causador_user_id and assigned_group_id
print(f"\n2️⃣ Bloco MODO 2 (CAUSADOR + GERENTES):")
print(f"  Condição: causador_user_id={causador_user_id} AND assigned_group_id={assigned_group_id}")
print(f"  Resultado: {condicao2}")
if not condicao1 and condicao2:  # Só executa se o primeiro NÃO executar
    print(f"  ✓ VAI EXECUTAR ESTE BLOCO")
    print(f"  → Vai compartilhar com: Causador + Gerentes + Ronaldo")
else:
    print(f"  ✗ NÃO VAI EXECUTAR ESTE BLOCO")

# Listar quem DEVERIA receber
print(f"\n" + "-"*80)
print("QUEM DEVERIA RECEBER ESTA RNC?")
print("-"*80)

expected_users = []

if condicao2 and not condicao1:
    # MODO 2: Causador + Gerentes
    expected_users = [CAUSADOR_ID, GERENTE_ID, SUB_GERENTE_ID, RONALDO_ID]
    print(f"\n✓ Modo Causador Específico:")
    print(f"  1. Matheus Tocantins (Causador, ID: {CAUSADOR_ID})")
    print(f"  2. Guilherme (Gerente, ID: {GERENTE_ID})")
    print(f"  3. Cintia (Sub-Gerente, ID: {SUB_GERENTE_ID})")
    print(f"  4. Ronaldo (Valorista, ID: {RONALDO_ID})")
    print(f"\n  Total: {len(expected_users)} pessoas")

elif condicao1:
    # MODO 1: Todo o grupo
    cursor.execute('SELECT id, name FROM users WHERE group_id = ?', (GRUPO_ENGENHARIA_ID,))
    all_users = cursor.fetchall()
    expected_users = [u[0] for u in all_users]
    print(f"\n✓ Modo Todo o Grupo:")
    print(f"  Total: {len(expected_users)} pessoas (TODOS da Engenharia)")

print(f"\n" + "="*80)
print("CONCLUSÃO:")
print("="*80)

if condicao2 and not condicao1:
    print("\n✅ LÓGICA CORRETA!")
    print("  O código VAI executar o bloco MODO 2 (Causador + Gerentes)")
    print("  A RNC será enviada para 4 pessoas específicas")
elif condicao1:
    print("\n❌ PROBLEMA!")
    print("  O código VAI executar o bloco MODO 1 (Todo o Grupo)")
    print("  A RNC será enviada para TODOS os 31 usuários da Engenharia")
    print("  ISSO ESTÁ ERRADO!")
else:
    print("\n⚠️ ATENÇÃO!")
    print("  Nenhum dos blocos vai executar!")
    print("  A RNC não será compartilhada com ninguém!")

conn.close()
print("\n" + "="*80)
