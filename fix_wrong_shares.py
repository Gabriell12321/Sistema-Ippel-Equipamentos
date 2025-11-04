"""
CORREÇÃO: Remover compartilhamentos INDEVIDOS de RNCs com causador específico

PROBLEMA:
- RNCs antigas com causador_user_id preenchido foram compartilhadas com TODO o grupo
- Deveria ter ido apenas para causador + gerentes + Ronaldo

SOLUÇÃO:
- Encontrar RNCs com causador_user_id
- Remover compartilhamentos com usuários que NÃO são: causador, gerentes, Ronaldo
"""
import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

RONALDO_ID = 11

print("="*80)
print("CORREÇÃO: REMOVER COMPARTILHAMENTOS INDEVIDOS")
print("="*80)

# Buscar RNCs com causador específico
cursor.execute("""
    SELECT r.id, r.rnc_number, r.assigned_group_id, r.causador_user_id, r.user_id
    FROM rncs r
    WHERE r.causador_user_id IS NOT NULL
      AND r.assigned_group_id IS NOT NULL
      AND r.status != 'Finalizado'
    ORDER BY r.created_at DESC
""")
rncs_with_causador = cursor.fetchall()

print(f"\n📊 RNCs com causador específico encontradas: {len(rncs_with_causador)}")

if len(rncs_with_causador) == 0:
    print("\n✅ Não há RNCs para corrigir!")
    conn.close()
    exit(0)

# Contar quantos compartilhamentos indevidos existem
total_indevidos = 0
rncs_to_fix = []

for rnc in rncs_with_causador:
    rnc_id, rnc_number, group_id, causador_id, creator_id = rnc
    
    # Buscar gerentes do grupo
    cursor.execute("""
        SELECT manager_user_id, sub_manager_user_id
        FROM groups
        WHERE id = ?
    """, (group_id,))
    managers = cursor.fetchone()
    
    # Lista de usuários que DEVERIAM ter acesso
    allowed_users = [causador_id, RONALDO_ID]
    if managers:
        manager_id, sub_manager_id = managers
        if manager_id:
            allowed_users.append(manager_id)
        if sub_manager_id:
            allowed_users.append(sub_manager_id)
    
    # Buscar compartilhamentos INDEVIDOS (usuários que não estão na lista)
    cursor.execute("""
        SELECT shared_with_user_id
        FROM rnc_shares
        WHERE rnc_id = ?
          AND shared_with_user_id NOT IN ({})
    """.format(','.join('?' * len(allowed_users))), [rnc_id] + allowed_users)
    
    indevidos = cursor.fetchall()
    if len(indevidos) > 0:
        total_indevidos += len(indevidos)
        rncs_to_fix.append((rnc_id, rnc_number, len(indevidos)))

print(f"\nRNCs com compartilhamentos indevidos: {len(rncs_to_fix)}")
print(f"Total de compartilhamentos indevidos: {total_indevidos}")

if total_indevidos == 0:
    print(f"\n✅ Não há compartilhamentos indevidos!")
    conn.close()
    exit(0)

# Mostrar primeiros 10
print(f"\n📋 Primeiras 10 RNCs:")
for rnc in rncs_to_fix[:10]:
    rnc_id, rnc_number, count = rnc
    print(f"  • RNC-{rnc_number}: {count} compartilhamentos indevidos")

print(f"\n⚠️ ATENÇÃO: Este script vai REMOVER {total_indevidos} compartilhamentos indevidos")
print("Deseja continuar? (Digite 'SIM' para confirmar)")
response = input("> ")

if response.upper() != 'SIM':
    print("\n❌ Correção cancelada!")
    conn.close()
    exit(0)

print(f"\n{'='*80}")
print("INICIANDO CORREÇÃO...")
print(f"{'='*80}\n")

fixed_count = 0
removed_total = 0

for rnc in rncs_with_causador:
    rnc_id, rnc_number, group_id, causador_id, creator_id = rnc
    
    # Buscar gerentes
    cursor.execute("""
        SELECT manager_user_id, sub_manager_user_id
        FROM groups
        WHERE id = ?
    """, (group_id,))
    managers = cursor.fetchone()
    
    # Lista de usuários permitidos
    allowed_users = [causador_id, RONALDO_ID]
    if managers:
        manager_id, sub_manager_id = managers
        if manager_id:
            allowed_users.append(manager_id)
        if sub_manager_id:
            allowed_users.append(sub_manager_id)
    
    # Remover compartilhamentos indevidos
    cursor.execute("""
        DELETE FROM rnc_shares
        WHERE rnc_id = ?
          AND shared_with_user_id NOT IN ({})
    """.format(','.join('?' * len(allowed_users))), [rnc_id] + allowed_users)
    
    removed = cursor.rowcount
    if removed > 0:
        print(f"RNC-{rnc_number}: {removed} compartilhamentos removidos")
        fixed_count += 1
        removed_total += removed

# Commit
conn.commit()

print(f"\n{'='*80}")
print("RESUMO DA CORREÇÃO:")
print(f"{'='*80}")
print(f"  RNCs corrigidas: {fixed_count}")
print(f"  Compartilhamentos removidos: {removed_total}")

print(f"\n✅ CORREÇÃO CONCLUÍDA COM SUCESSO!")

conn.close()
print(f"\n{'='*80}\n")
