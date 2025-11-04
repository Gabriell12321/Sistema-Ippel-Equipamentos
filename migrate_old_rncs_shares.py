"""
Script de MIGRAÇÃO: Corrigir RNCs antigas que não foram compartilhadas corretamente

PROBLEMA:
- RNCs antigas têm assigned_group_id mas NÃO têm registros em rnc_shares
- Isso faz com que apareçam para todos do grupo (bug antigo)

SOLUÇÃO:
- Para cada RNC com assigned_group_id:
  - Se causador_user_id preenchido → compartilhar com causador + gerentes + Ronaldo
  - Se causador_user_id vazio → compartilhar com TODO o grupo
"""
import sqlite3
from datetime import datetime

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

RONALDO_ID = 11  # Valorista

print("="*80)
print("MIGRAÇÃO: CORRIGIR RNCs ANTIGAS SEM rnc_shares")
print("="*80)

# Buscar RNCs que têm assigned_group_id mas não têm compartilhamentos
cursor.execute("""
    SELECT r.id, r.rnc_number, r.assigned_group_id, r.causador_user_id, r.user_id
    FROM rncs r
    WHERE r.assigned_group_id IS NOT NULL
      AND r.status != 'Finalizado'
      AND NOT EXISTS (
          SELECT 1 FROM rnc_shares rs 
          WHERE rs.rnc_id = r.id
      )
    ORDER BY r.created_at DESC
""")
rncs_to_fix = cursor.fetchall()

print(f"\n📊 RNCs encontradas para migração: {len(rncs_to_fix)}")

if len(rncs_to_fix) == 0:
    print("\n✅ Não há RNCs para migrar!")
    conn.close()
    exit(0)

print(f"\n⚠️ ATENÇÃO: Este script vai adicionar {len(rncs_to_fix)} RNCs em rnc_shares")
print("Deseja continuar? (Digite 'SIM' para confirmar)")
response = input("> ")

if response.upper() != 'SIM':
    print("\n❌ Migração cancelada!")
    conn.close()
    exit(0)

print(f"\n{'='*80}")
print("INICIANDO MIGRAÇÃO...")
print(f"{'='*80}\n")

fixed_count = 0
errors = []

for rnc in rncs_to_fix:
    rnc_id, rnc_number, group_id, causador_id, creator_id = rnc
    
    try:
        print(f"RNC-{rnc_number} (ID: {rnc_id}):")
        
        if causador_id:
            # MODO 2: Causador específico → compartilhar com causador + gerentes + Ronaldo
            print(f"  • Modo: Causador específico (ID: {causador_id})")
            
            users_to_share = [causador_id]
            
            # Buscar gerentes do grupo
            cursor.execute("""
                SELECT manager_user_id, sub_manager_user_id
                FROM groups
                WHERE id = ?
            """, (group_id,))
            managers = cursor.fetchone()
            
            if managers:
                manager_id, sub_manager_id = managers
                if manager_id and manager_id not in users_to_share and manager_id != creator_id:
                    users_to_share.append(manager_id)
                    print(f"    - Gerente (ID: {manager_id})")
                if sub_manager_id and sub_manager_id not in users_to_share and sub_manager_id != creator_id:
                    users_to_share.append(sub_manager_id)
                    print(f"    - Sub-gerente (ID: {sub_manager_id})")
            
            # Adicionar Ronaldo
            if RONALDO_ID not in users_to_share and RONALDO_ID != creator_id:
                users_to_share.append(RONALDO_ID)
                print(f"    - Ronaldo/Valorista (ID: {RONALDO_ID})")
            
            # Compartilhar com cada usuário
            for user_id in users_to_share:
                if user_id != creator_id:
                    cursor.execute("""
                        INSERT INTO rnc_shares 
                        (rnc_id, shared_by_user_id, shared_with_user_id, permission_level)
                        VALUES (?, ?, ?, 'assigned')
                    """, (rnc_id, creator_id, user_id))
            
            print(f"  ✓ Compartilhada com {len(users_to_share)} usuários")
            
        else:
            # MODO 1: Todo o grupo → compartilhar com todos os usuários do grupo
            print(f"  • Modo: Todo o grupo")
            
            # Buscar todos os usuários do grupo
            cursor.execute("""
                SELECT id FROM users WHERE group_id = ?
            """, (group_id,))
            group_users = cursor.fetchall()
            
            shared_count = 0
            for user_row in group_users:
                user_id = user_row[0]
                if user_id != creator_id:
                    cursor.execute("""
                        INSERT INTO rnc_shares 
                        (rnc_id, shared_by_user_id, shared_with_user_id, permission_level)
                        VALUES (?, ?, ?, 'assigned')
                    """, (rnc_id, creator_id, user_id))
                    shared_count += 1
            
            print(f"  ✓ Compartilhada com {shared_count} usuários do grupo")
        
        fixed_count += 1
        
    except Exception as e:
        error_msg = f"RNC-{rnc_number}: {str(e)}"
        errors.append(error_msg)
        print(f"  ✗ ERRO: {e}")

# Commit das alterações
conn.commit()

print(f"\n{'='*80}")
print("RESUMO DA MIGRAÇÃO:")
print(f"{'='*80}")
print(f"  Total de RNCs migradas: {fixed_count}/{len(rncs_to_fix)}")
print(f"  Erros: {len(errors)}")

if errors:
    print(f"\n❌ Erros encontrados:")
    for error in errors[:10]:
        print(f"    - {error}")

if fixed_count == len(rncs_to_fix):
    print(f"\n✅ MIGRAÇÃO CONCLUÍDA COM SUCESSO!")
else:
    print(f"\n⚠️ Migração concluída com {len(errors)} erros")

conn.close()
print(f"\n{'='*80}\n")
