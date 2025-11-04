"""
Teste após correção: verificar se Matheus vê apenas as RNCs corretas
"""
import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

print("="*80)
print("TESTE PÓS-CORREÇÃO: RNCs VISÍVEIS PARA MATHEUS")
print("="*80)

# ID do Matheus Tocantins
MATHEUS_ID = 153

# Simular a query CORRIGIDA do dashboard
cursor.execute("""
    SELECT DISTINCT r.id, r.rnc_number, r.status, r.causador_user_id
    FROM rncs r
    LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id
    WHERE (r.is_deleted = 0 OR r.is_deleted IS NULL)
      AND r.status != 'Finalizado'
      AND (
          r.user_id = ?
          OR r.assigned_user_id = ?
          OR rs.shared_with_user_id = ?
      )
    ORDER BY r.created_at DESC
""", (MATHEUS_ID, MATHEUS_ID, MATHEUS_ID))

visible_rncs = cursor.fetchall()

print(f"\n✅ RNCs que Matheus DEVERIA ver (query corrigida):")
print(f"   Total: {len(visible_rncs)}")

if len(visible_rncs) > 0:
    for rnc in visible_rncs:
        rnc_id, rnc_number, status, causador_id = rnc
        causador_nome = "NENHUM"
        if causador_id:
            cursor.execute("SELECT name FROM users WHERE id = ?", (causador_id,))
            c = cursor.fetchone()
            causador_nome = c[0] if c else f"ID:{causador_id}"
        print(f"   • RNC-{rnc_number} (ID: {rnc_id}) - {status} - Causador: {causador_nome}")
else:
    print("   (Nenhuma RNC)")

# Verificar se ele está vendo RNCs que NÃO deveria ver
print(f"\n{'='*80}")
print("🔍 VERIFICAÇÃO: RNCs do grupo que NÃO deveriam aparecer:")

cursor.execute("""
    SELECT r.id, r.rnc_number, r.causador_user_id
    FROM rncs r
    WHERE r.assigned_group_id = 7
      AND r.status != 'Finalizado'
      AND r.user_id != ?
      AND r.id NOT IN (
          SELECT rnc_id FROM rnc_shares WHERE shared_with_user_id = ?
      )
    ORDER BY r.created_at DESC
""", (MATHEUS_ID, MATHEUS_ID))

should_not_see = cursor.fetchall()

print(f"   Total: {len(should_not_see)}")
if len(should_not_see) > 0:
    print(f"   ⚠️ Se Matheus está vendo estas RNCs, ainda há um problema!")
    for rnc in should_not_see[:5]:
        rnc_id, rnc_number, causador_id = rnc
        causador_nome = "NENHUM"
        if causador_id:
            cursor.execute("SELECT name FROM users WHERE id = ?", (causador_id,))
            c = cursor.fetchone()
            causador_nome = c[0] if c else f"ID:{causador_id}"
        print(f"   • RNC-{rnc_number} (ID: {rnc_id}) - Causador: {causador_nome}")
else:
    print(f"   ✅ Nenhuma RNC indevida! Correção funcionou!")

print(f"\n{'='*80}")
print("CONCLUSÃO:")
print(f"  Matheus deveria ver: {len(visible_rncs)} RNCs")
print(f"  Matheus NÃO deveria ver: {len(should_not_see)} RNCs")

if len(should_not_see) == 0:
    print(f"\n  ✅ SUCESSO! A correção está funcionando corretamente!")
else:
    print(f"\n  ❌ Ainda há {len(should_not_see)} RNCs aparecendo indevidamente!")

conn.close()
print("\n" + "="*80)
