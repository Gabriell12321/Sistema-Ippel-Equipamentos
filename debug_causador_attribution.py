"""
Script para debugar o problema de atribuição com causador_user_id

Verifica o que acontece quando uma RNC é criada com usuário causador especificado
"""
import sqlite3
import sys

# Conectar ao banco
conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

print("="*80)
print("DEBUG: ATRIBUIÇÃO DE RNC COM CAUSADOR")
print("="*80)

# Buscar a RNC mais recente
cursor.execute('''
    SELECT id, rnc_number, causador_user_id, assigned_group_id, created_at
    FROM rncs
    ORDER BY created_at DESC
    LIMIT 1
''')
rnc = cursor.fetchone()

if not rnc:
    print("❌ Nenhuma RNC encontrada!")
    sys.exit(1)

rnc_id, rnc_number, causador_id, group_id, created_at = rnc

print(f"\n📋 RNC Mais Recente:")
print(f"  - ID: {rnc_id}")
print(f"  - Número: {rnc_number}")
print(f"  - Causador User ID: {causador_id}")
print(f"  - Grupo Atribuído: {group_id}")
print(f"  - Criada em: {created_at}")

# Buscar nome do causador (se houver)
if causador_id:
    cursor.execute('SELECT name FROM users WHERE id = ?', (causador_id,))
    causador = cursor.fetchone()
    print(f"  - Nome do Causador: {causador[0] if causador else 'NÃO ENCONTRADO'}")
else:
    print(f"  - ⚠️ Causador: VAZIO (deveria ir para TODO O GRUPO)")

# Buscar nome do grupo
if group_id:
    cursor.execute('SELECT name FROM groups WHERE id = ?', (group_id,))
    group = cursor.fetchone()
    print(f"  - Nome do Grupo: {group[0] if group else 'NÃO ENCONTRADO'}")

# Buscar TODOS os usuários que receberam a RNC
print(f"\n👥 Usuários que RECEBERAM esta RNC:")
cursor.execute('''
    SELECT u.id, u.name, u.group_id, rs.permission_level
    FROM rnc_shares rs
    JOIN users u ON rs.shared_with_user_id = u.id
    WHERE rs.rnc_id = ?
    ORDER BY u.name
''', (rnc_id,))
shared_users = cursor.fetchall()

if shared_users:
    print(f"  Total: {len(shared_users)} usuários")
    for user in shared_users:
        uid, uname, ugroupid, perm = user
        print(f"    • {uname} (ID: {uid}, Grupo: {ugroupid}, Permissão: {perm})")
else:
    print("  ❌ Nenhum usuário recebeu esta RNC!")

# Buscar TODOS os usuários do grupo
if group_id:
    print(f"\n👥 TODOS os usuários do grupo {group[0] if group else group_id}:")
    cursor.execute('SELECT id, name FROM users WHERE group_id = ? ORDER BY name', (group_id,))
    all_group_users = cursor.fetchall()
    print(f"  Total: {len(all_group_users)} usuários")
    for user in all_group_users:
        uid, uname = user
        received = "✓ RECEBEU" if any(u[0] == uid for u in shared_users) else "✗ NÃO RECEBEU"
        print(f"    • {uname} (ID: {uid}) - {received}")

# Buscar gerentes do grupo
if group_id:
    print(f"\n👔 Gerentes do grupo:")
    cursor.execute('''
        SELECT manager_user_id, sub_manager_user_id
        FROM groups
        WHERE id = ?
    ''', (group_id,))
    managers = cursor.fetchone()
    if managers:
        manager_id, sub_manager_id = managers
        if manager_id:
            cursor.execute('SELECT name FROM users WHERE id = ?', (manager_id,))
            manager = cursor.fetchone()
            print(f"  - Gerente Principal: {manager[0] if manager else 'N/A'} (ID: {manager_id})")
        if sub_manager_id:
            cursor.execute('SELECT name FROM users WHERE id = ?', (sub_manager_id,))
            sub_manager = cursor.fetchone()
            print(f"  - Sub-Gerente: {sub_manager[0] if sub_manager else 'N/A'} (ID: {sub_manager_id})")
    else:
        print("  ❌ Nenhum gerente configurado para este grupo!")

# Análise da situação
print(f"\n🔍 ANÁLISE:")
if causador_id:
    # Deveria ir para: causador + gerentes + Ronaldo (ID 11)
    expected_users = [causador_id]
    if managers and managers[0]:
        expected_users.append(managers[0])
    if managers and managers[1]:
        expected_users.append(managers[1])
    if 11 not in expected_users:  # Ronaldo
        expected_users.append(11)
    
    print(f"  ✓ Causador PREENCHIDO")
    print(f"  📌 Deveria ir para: {len(expected_users)} pessoas")
    print(f"     - Causador (ID: {causador_id})")
    if managers and managers[0]:
        cursor.execute('SELECT name FROM users WHERE id = ?', (managers[0],))
        mgr = cursor.fetchone()
        print(f"     - Gerente (ID: {managers[0]}, {mgr[0] if mgr else 'N/A'})")
    if managers and managers[1]:
        cursor.execute('SELECT name FROM users WHERE id = ?', (managers[1],))
        sub = cursor.fetchone()
        print(f"     - Sub-Gerente (ID: {managers[1]}, {sub[0] if sub else 'N/A'})")
    print(f"     - Ronaldo - Valorista (ID: 11)")
    
    print(f"\n  📊 Situação ATUAL:")
    print(f"     - {len(shared_users)} usuários receberam a RNC")
    
    if len(shared_users) > len(expected_users):
        print(f"     - ❌ PROBLEMA: Mais usuários receberam do que deveriam!")
        print(f"     - Usuários extras: {len(shared_users) - len(expected_users)}")
    elif len(shared_users) < len(expected_users):
        print(f"     - ⚠️ ATENÇÃO: Menos usuários receberam do que deveriam!")
        print(f"     - Usuários faltando: {len(expected_users) - len(shared_users)}")
    else:
        print(f"     - ✓ Quantidade correta!")
        
        # Verificar se são as pessoas certas
        received_ids = [u[0] for u in shared_users]
        wrong_users = [uid for uid in received_ids if uid not in expected_users]
        missing_users = [uid for uid in expected_users if uid not in received_ids]
        
        if wrong_users:
            print(f"     - ❌ Usuários ERRADOS receberam: {wrong_users}")
        if missing_users:
            print(f"     - ❌ Usuários ESPERADOS NÃO receberam: {missing_users}")
        if not wrong_users and not missing_users:
            print(f"     - ✓✓ Todas as pessoas certas receberam!")
else:
    print(f"  ✓ Causador VAZIO")
    print(f"  📌 Deveria ir para: TODO O GRUPO ({len(all_group_users)} pessoas)")
    
    if len(shared_users) == len(all_group_users):
        print(f"     - ✓ Todos os usuários do grupo receberam!")
    else:
        print(f"     - ❌ Apenas {len(shared_users)} de {len(all_group_users)} receberam!")

conn.close()
print("\n" + "="*80)
