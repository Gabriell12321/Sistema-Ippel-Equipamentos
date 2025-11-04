"""
Buscar usuários do grupo Engenharia
"""
import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

print("="*80)
print("USUÁRIOS DO GRUPO ENGENHARIA")
print("="*80)

cursor.execute('''
    SELECT id, name, email
    FROM users
    WHERE group_id = 7
    ORDER BY name
''')
users = cursor.fetchall()

print(f"\nTotal: {len(users)} usuários\n")

for user in users:
    uid, name, email = user
    print(f"  • ID: {uid:3d} | {name} | {email or 'sem email'}")

# Buscar especificamente Matheus
print("\n" + "-"*80)
print("Buscando 'Matheus':")
cursor.execute('''
    SELECT id, name, email, group_id
    FROM users
    WHERE name LIKE '%Matheus%' OR name LIKE '%matheus%'
    ORDER BY name
''')
matheus_users = cursor.fetchall()

if matheus_users:
    for user in matheus_users:
        uid, name, email, gid = user
        cursor.execute('SELECT name FROM groups WHERE id = ?', (gid,))
        group = cursor.fetchone()
        group_name = group[0] if group else 'SEM GRUPO'
        print(f"  • ID: {uid:3d} | {name} | Grupo: {group_name} (ID: {gid})")
else:
    print("  ❌ Nenhum usuário 'Matheus' encontrado!")

conn.close()
print("\n" + "="*80)
