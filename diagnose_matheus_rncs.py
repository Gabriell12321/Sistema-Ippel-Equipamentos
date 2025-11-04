"""
Verificar quais RNCs o usuário Matheus Tocantins está vendo
"""
import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

print("="*80)
print("DIAGNÓSTICO: RNCs VISÍVEIS PARA MATHEUS TOCANTINS")
print("="*80)

# Buscar ID do Matheus Tocantins
cursor.execute("SELECT id, name, group_id FROM users WHERE name LIKE '%Matheus Tocantins%'")
matheus = cursor.fetchone()

if not matheus:
    print("❌ Usuário Matheus Tocantins não encontrado!")
    exit(1)

matheus_id, matheus_name, matheus_group = matheus
print(f"\n👤 Usuário: {matheus_name}")
print(f"  - ID: {matheus_id}")
print(f"  - Grupo ID: {matheus_group}")

# Buscar nome do grupo
cursor.execute("SELECT name FROM groups WHERE id = ?", (matheus_group,))
group = cursor.fetchone()
print(f"  - Grupo: {group[0] if group else 'N/A'}")

# Contar RNCs TOTAIS no sistema
cursor.execute("SELECT COUNT(*) FROM rncs WHERE status != 'Finalizado'")
total_rncs = cursor.fetchone()[0]
print(f"\n📊 Total de RNCs ATIVAS no sistema: {total_rncs}")

# 1. RNCs CRIADAS por Matheus
print(f"\n{'='*80}")
print("1️⃣ RNCs CRIADAS por Matheus:")
cursor.execute("""
    SELECT id, rnc_number, status, created_at
    FROM rncs
    WHERE user_id = ? AND status != 'Finalizado'
    ORDER BY created_at DESC
    LIMIT 10
""", (matheus_id,))
created_rncs = cursor.fetchall()
print(f"  Total: {len(created_rncs)}")
for rnc in created_rncs[:5]:
    print(f"    • RNC-{rnc[1]} (ID: {rnc[0]}) - {rnc[2]}")

# 2. RNCs COMPARTILHADAS com Matheus
print(f"\n{'='*80}")
print("2️⃣ RNCs COMPARTILHADAS diretamente com Matheus:")
cursor.execute("""
    SELECT r.id, r.rnc_number, r.status, rs.permission_level, r.created_at
    FROM rnc_shares rs
    JOIN rncs r ON rs.rnc_id = r.id
    WHERE rs.shared_with_user_id = ? AND r.status != 'Finalizado'
    ORDER BY r.created_at DESC
    LIMIT 10
""", (matheus_id,))
shared_rncs = cursor.fetchall()
print(f"  Total: {len(shared_rncs)}")
for rnc in shared_rncs[:5]:
    print(f"    • RNC-{rnc[1]} (ID: {rnc[0]}) - {rnc[2]} - Permissão: {rnc[3]}")

# 3. RNCs do GRUPO de Matheus (assigned_group_id)
print(f"\n{'='*80}")
print(f"3️⃣ RNCs atribuídas ao grupo ENGENHARIA (ID: {matheus_group}):")
cursor.execute("""
    SELECT id, rnc_number, status, causador_user_id, created_at
    FROM rncs
    WHERE assigned_group_id = ? AND status != 'Finalizado'
    ORDER BY created_at DESC
    LIMIT 10
""", (matheus_group,))
group_rncs = cursor.fetchall()
print(f"  Total: {len(group_rncs)}")
for rnc in group_rncs[:5]:
    causador_id = rnc[3]
    causador_nome = "VAZIO"
    if causador_id:
        cursor.execute("SELECT name FROM users WHERE id = ?", (causador_id,))
        c = cursor.fetchone()
        causador_nome = c[0] if c else f"ID:{causador_id}"
    print(f"    • RNC-{rnc[1]} (ID: {rnc[0]}) - {rnc[2]} - Causador: {causador_nome}")

# 4. ANÁLISE: Quais RNCs Matheus DEVERIA ver vs ESTÁ vendo
print(f"\n{'='*80}")
print("🔍 ANÁLISE:")
print(f"  Matheus DEVERIA ver:")
print(f"    - RNCs que ele criou: {len(created_rncs)}")
print(f"    - RNCs compartilhadas com ele: {len(shared_rncs)}")
print(f"    - Total esperado: {len(created_rncs) + len(shared_rncs)}")

# Verificar se há RNCs do grupo que NÃO foram compartilhadas com Matheus
print(f"\n  RNCs do grupo Engenharia que NÃO foram compartilhadas com Matheus:")
cursor.execute("""
    SELECT r.id, r.rnc_number, r.causador_user_id
    FROM rncs r
    WHERE r.assigned_group_id = ? 
      AND r.status != 'Finalizado'
      AND r.user_id != ?
      AND r.id NOT IN (
          SELECT rnc_id FROM rnc_shares WHERE shared_with_user_id = ?
      )
    ORDER BY r.created_at DESC
    LIMIT 10
""", (matheus_group, matheus_id, matheus_id))
unshared_group_rncs = cursor.fetchall()

print(f"    Total: {len(unshared_group_rncs)}")
if len(unshared_group_rncs) > 0:
    print(f"    ❌ PROBLEMA: Há {len(unshared_group_rncs)} RNCs do grupo que NÃO foram compartilhadas!")
    for rnc in unshared_group_rncs[:5]:
        causador_id = rnc[2]
        causador_nome = "VAZIO"
        if causador_id:
            cursor.execute("SELECT name FROM users WHERE id = ?", (causador_id,))
            c = cursor.fetchone()
            causador_nome = c[0] if c else f"ID:{causador_id}"
        print(f"      • RNC-{rnc[1]} (ID: {rnc[0]}) - Causador: {causador_nome}")
        
        # Se o causador foi especificado e NÃO é Matheus, isso é um problema!
        if causador_id and causador_id != matheus_id:
            print(f"        ⚠️ Esta RNC tem causador específico ({causador_nome}) e NÃO deveria aparecer para Matheus!")

# 5. Verificar a query que o dashboard usa
print(f"\n{'='*80}")
print("📋 VERIFICANDO LÓGICA DO DASHBOARD:")
print("O dashboard provavelmente mostra RNCs baseado em:")
print("  A. RNCs criadas pelo usuário (user_id)")
print("  B. RNCs compartilhadas (rnc_shares)")
print("  C. RNCs do grupo do usuário (assigned_group_id) ← AQUI ESTÁ O PROBLEMA!")

print(f"\n⚠️ Se o dashboard está mostrando TODAS as RNCs do grupo,")
print(f"   sem verificar se foram compartilhadas, isso explica o problema!")

conn.close()
print("\n" + "="*80)
