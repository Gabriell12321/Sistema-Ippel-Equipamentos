"""
Verificar configuração de gerentes dos grupos
"""
import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

print("="*80)
print("CONFIGURAÇÃO DE GERENTES POR GRUPO")
print("="*80)

# Buscar todos os grupos
cursor.execute('SELECT id, name FROM groups ORDER BY name')
groups = cursor.fetchall()

for group in groups:
    group_id, group_name = group
    
    # Buscar gerentes
    cursor.execute('''
        SELECT manager_user_id, sub_manager_user_id
        FROM groups
        WHERE id = ?
    ''', (group_id,))
    managers = cursor.fetchone()
    
    print(f"\n📁 Grupo: {group_name} (ID: {group_id})")
    
    if managers:
        manager_id, sub_manager_id = managers
        
        if manager_id:
            cursor.execute('SELECT name FROM users WHERE id = ?', (manager_id,))
            manager = cursor.fetchone()
            print(f"  👔 Gerente: {manager[0] if manager else 'USUÁRIO NÃO ENCONTRADO'} (ID: {manager_id})")
        else:
            print(f"  ⚠️ Gerente: NÃO CONFIGURADO")
            
        if sub_manager_id:
            cursor.execute('SELECT name FROM users WHERE id = ?', (sub_manager_id,))
            sub_manager = cursor.fetchone()
            print(f"  👔 Sub-Gerente: {sub_manager[0] if sub_manager else 'USUÁRIO NÃO ENCONTRADO'} (ID: {sub_manager_id})")
        else:
            print(f"  ⚠️ Sub-Gerente: NÃO CONFIGURADO")
    else:
        print(f"  ❌ SEM GERENTES CONFIGURADOS")
    
    # Contar usuários do grupo
    cursor.execute('SELECT COUNT(*) FROM users WHERE group_id = ?', (group_id,))
    user_count = cursor.fetchone()[0]
    print(f"  👥 Total de usuários: {user_count}")

conn.close()
print("\n" + "="*80)
