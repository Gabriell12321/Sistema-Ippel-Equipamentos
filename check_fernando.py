import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()
cursor.execute("SELECT id, name, email FROM users WHERE email LIKE '%fernando%' OR name LIKE '%Fernando%'")
results = cursor.fetchall()
print("Usuários Fernando:")
for u in results:
    print(f"{u[0]:3d} | {u[1]:30s} | {u[2]}")
conn.close()
