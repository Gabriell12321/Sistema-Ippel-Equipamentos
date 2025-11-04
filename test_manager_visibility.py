"""
Teste de visibilidade de RNCs para gerentes/sub-gerentes

Verifica se Guilherme (gerente) e Cintia (sub-gerente) conseguem ver
TODAS as RNCs do grupo Engenharia, independente do causador
"""
import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

print("="*80)
print("TESTE DE VISIBILIDADE PARA GERENTES/SUB-GERENTES")
print("="*80)

# IDs importantes
GUILHERME_ID = 14  # Gerente da Engenharia
CINTIA_ID = 13     # Sub-Gerente da Engenharia
MATHEUS_ID = 153   # Usuário normal da Engenharia
ENGENHARIA_ID = 7  # Grupo Engenharia

# Verificar configuração dos gerentes
print(f"\n📋 Configuração do Grupo Engenharia:")
cursor.execute('''
    SELECT name, manager_user_id, sub_manager_user_id
    FROM groups
    WHERE id = ?
''', (ENGENHARIA_ID,))
group = cursor.fetchone()

if group:
    print(f"  Nome: {group[0]}")
    
    if group[1]:
        cursor.execute('SELECT name FROM users WHERE id = ?', (group[1],))
        manager = cursor.fetchone()
        print(f"  Gerente: {manager[0] if manager else 'N/A'} (ID: {group[1]})")
    else:
        print(f"  Gerente: NÃO CONFIGURADO")
    
    if group[2]:
        cursor.execute('SELECT name FROM users WHERE id = ?', (group[2],))
        sub_manager = cursor.fetchone()
        print(f"  Sub-Gerente: {sub_manager[0] if sub_manager else 'N/A'} (ID: {group[2]})")
    else:
        print(f"  Sub-Gerente: NÃO CONFIGURADO")

# Contar RNCs totais do grupo Engenharia
print(f"\n" + "-"*80)
cursor.execute('''
    SELECT COUNT(*)
    FROM rncs
    WHERE assigned_group_id = ? AND status NOT IN ('Finalizado') AND (is_deleted = 0 OR is_deleted IS NULL)
''', (ENGENHARIA_ID,))
total_rncs_eng = cursor.fetchone()[0]
print(f"Total de RNCs ATIVAS da Engenharia: {total_rncs_eng}")

# Contar RNCs COM causador específico
cursor.execute('''
    SELECT COUNT(*)
    FROM rncs
    WHERE assigned_group_id = ? 
      AND causador_user_id IS NOT NULL
      AND status NOT IN ('Finalizado')
      AND (is_deleted = 0 OR is_deleted IS NULL)
''', (ENGENHARIA_ID,))
rncs_com_causador = cursor.fetchone()[0]
print(f"  - Com causador específico: {rncs_com_causador}")

# Contar RNCs SEM causador
cursor.execute('''
    SELECT COUNT(*)
    FROM rncs
    WHERE assigned_group_id = ? 
      AND (causador_user_id IS NULL OR causador_user_id = '')
      AND status NOT IN ('Finalizado')
      AND (is_deleted = 0 OR is_deleted IS NULL)
''', (ENGENHARIA_ID,))
rncs_sem_causador = cursor.fetchone()[0]
print(f"  - Sem causador (todo o grupo): {rncs_sem_causador}")

# Testar a query para GUILHERME (gerente)
print(f"\n" + "="*80)
print(f"TESTE 1: GUILHERME (Gerente)")
print("="*80)

user_id = GUILHERME_ID

cursor.execute('''
    SELECT DISTINCT r.id, r.rnc_number, r.causador_user_id
    FROM rncs r
    LEFT JOIN users u ON r.user_id = u.id
    LEFT JOIN users au ON r.assigned_user_id = au.id
    LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id
    LEFT JOIN users user_group_active ON user_group_active.id = ?
    WHERE (r.is_deleted = 0 OR r.is_deleted IS NULL)
      AND r.status NOT IN ('Finalizado')
      AND (
          r.user_id = ?
          OR r.assigned_user_id = ?
          OR rs.shared_with_user_id = ?
          OR (r.assigned_group_id IS NOT NULL AND EXISTS (
              SELECT 1 FROM groups g 
              WHERE g.id = r.assigned_group_id 
                AND (g.manager_user_id = ? OR g.sub_manager_user_id = ?)
          ))
      )
    ORDER BY r.id DESC
''', (user_id, user_id, user_id, user_id, user_id, user_id))

guilherme_rncs = cursor.fetchall()
print(f"\nGuilherme vê: {len(guilherme_rncs)} RNCs")

if len(guilherme_rncs) == total_rncs_eng:
    print(f"✅ CORRETO! Guilherme vê TODAS as {total_rncs_eng} RNCs do grupo")
else:
    print(f"❌ ERRO! Guilherme deveria ver {total_rncs_eng} RNCs, mas vê apenas {len(guilherme_rncs)}")
    print(f"   Diferença: {total_rncs_eng - len(guilherme_rncs)} RNCs faltando")

# Mostrar algumas RNCs
print(f"\nExemplos de RNCs que Guilherme vê:")
for i, rnc in enumerate(guilherme_rncs[:5]):
    rnc_id, rnc_number, causador = rnc
    causador_info = f"Causador ID: {causador}" if causador else "Sem causador"
    print(f"  {i+1}. RNC {rnc_number} (ID: {rnc_id}) - {causador_info}")

# Testar a query para CINTIA (sub-gerente)
print(f"\n" + "="*80)
print(f"TESTE 2: CINTIA (Sub-Gerente)")
print("="*80)

user_id = CINTIA_ID

cursor.execute('''
    SELECT DISTINCT r.id, r.rnc_number, r.causador_user_id
    FROM rncs r
    LEFT JOIN users u ON r.user_id = u.id
    LEFT JOIN users au ON r.assigned_user_id = au.id
    LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id
    LEFT JOIN users user_group_active ON user_group_active.id = ?
    WHERE (r.is_deleted = 0 OR r.is_deleted IS NULL)
      AND r.status NOT IN ('Finalizado')
      AND (
          r.user_id = ?
          OR r.assigned_user_id = ?
          OR rs.shared_with_user_id = ?
          OR (r.assigned_group_id IS NOT NULL AND EXISTS (
              SELECT 1 FROM groups g 
              WHERE g.id = r.assigned_group_id 
                AND (g.manager_user_id = ? OR g.sub_manager_user_id = ?)
          ))
      )
    ORDER BY r.id DESC
''', (user_id, user_id, user_id, user_id, user_id, user_id))

cintia_rncs = cursor.fetchall()
print(f"\nCintia vê: {len(cintia_rncs)} RNCs")

if len(cintia_rncs) == total_rncs_eng:
    print(f"✅ CORRETO! Cintia vê TODAS as {total_rncs_eng} RNCs do grupo")
else:
    print(f"❌ ERRO! Cintia deveria ver {total_rncs_eng} RNCs, mas vê apenas {len(cintia_rncs)}")
    print(f"   Diferença: {total_rncs_eng - len(cintia_rncs)} RNCs faltando")

# Mostrar algumas RNCs
print(f"\nExemplos de RNCs que Cintia vê:")
for i, rnc in enumerate(cintia_rncs[:5]):
    rnc_id, rnc_number, causador = rnc
    causador_info = f"Causador ID: {causador}" if causador else "Sem causador"
    print(f"  {i+1}. RNC {rnc_number} (ID: {rnc_id}) - {causador_info}")

# Testar a query para MATHEUS (usuário normal)
print(f"\n" + "="*80)
print(f"TESTE 3: MATHEUS (Usuário Normal)")
print("="*80)

user_id = MATHEUS_ID

cursor.execute('''
    SELECT DISTINCT r.id, r.rnc_number, r.causador_user_id
    FROM rncs r
    LEFT JOIN users u ON r.user_id = u.id
    LEFT JOIN users au ON r.assigned_user_id = au.id
    LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id
    LEFT JOIN users user_group_active ON user_group_active.id = ?
    WHERE (r.is_deleted = 0 OR r.is_deleted IS NULL)
      AND r.status NOT IN ('Finalizado')
      AND (
          r.user_id = ?
          OR r.assigned_user_id = ?
          OR rs.shared_with_user_id = ?
          OR (r.assigned_group_id IS NOT NULL AND EXISTS (
              SELECT 1 FROM groups g 
              WHERE g.id = r.assigned_group_id 
                AND (g.manager_user_id = ? OR g.sub_manager_user_id = ?)
          ))
      )
    ORDER BY r.id DESC
''', (user_id, user_id, user_id, user_id, user_id, user_id))

matheus_rncs = cursor.fetchall()
print(f"\nMatheus vê: {len(matheus_rncs)} RNCs")

# Matheus deveria ver apenas:
# 1. RNCs onde ele é o causador
# 2. RNCs sem causador (todo o grupo)
# 3. RNCs que ele criou

cursor.execute('''
    SELECT COUNT(*)
    FROM rncs r
    LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id
    WHERE (r.is_deleted = 0 OR r.is_deleted IS NULL)
      AND r.status NOT IN ('Finalizado')
      AND r.assigned_group_id = ?
      AND (
          r.user_id = ?
          OR r.causador_user_id = ?
          OR (r.causador_user_id IS NULL AND rs.shared_with_user_id = ?)
          OR ((r.causador_user_id IS NULL OR r.causador_user_id = '') AND rs.shared_with_user_id = ?)
      )
''', (ENGENHARIA_ID, user_id, user_id, user_id, user_id))

expected_matheus = cursor.fetchone()[0]

print(f"Matheus deveria ver: ~{expected_matheus} RNCs")
print(f"  (RNCs onde ele é causador + RNCs sem causador + RNCs que ele criou)")

if len(matheus_rncs) <= expected_matheus + 2:  # margem de erro
    print(f"✅ CORRETO! Matheus vê apenas as RNCs apropriadas")
else:
    print(f"⚠️ ATENÇÃO! Matheus pode estar vendo RNCs extras")

# Mostrar algumas RNCs
print(f"\nExemplos de RNCs que Matheus vê:")
for i, rnc in enumerate(matheus_rncs[:5]):
    rnc_id, rnc_number, causador = rnc
    if causador == MATHEUS_ID:
        causador_info = "✓ ELE é o causador"
    elif causador:
        causador_info = f"⚠️ Causador: ID {causador} (não é ele)"
    else:
        causador_info = "✓ Sem causador (todo o grupo)"
    print(f"  {i+1}. RNC {rnc_number} (ID: {rnc_id}) - {causador_info}")

print(f"\n" + "="*80)
print("RESUMO:")
print("="*80)
print(f"Total RNCs Engenharia (ativas): {total_rncs_eng}")
print(f"Guilherme (gerente) vê: {len(guilherme_rncs)} - {'✅ OK' if len(guilherme_rncs) == total_rncs_eng else '❌ ERRO'}")
print(f"Cintia (sub-gerente) vê: {len(cintia_rncs)} - {'✅ OK' if len(cintia_rncs) == total_rncs_eng else '❌ ERRO'}")
print(f"Matheus (usuário) vê: {len(matheus_rncs)} - {'✅ OK' if len(matheus_rncs) < total_rncs_eng else '⚠️ REVISAR'}")
print("="*80)

conn.close()
