import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

print("=" * 70)
print("VERIFICANDO CONSTRAINT UNIQUE NA TABELA RNCS")
print("=" * 70)

# Ver índices
cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='rncs'")
indices = cursor.fetchall()

print("\n📋 ÍNDICES:")
for name, sql in indices:
    print(f"  - {name}")
    if sql:
        print(f"    SQL: {sql}")
    else:
        print(f"    (Índice automático - gerado por UNIQUE constraint)")

# Ver estrutura da tabela
cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='rncs'")
table_sql = cursor.fetchone()[0]

print("\n📋 CREATE TABLE:")
print(table_sql[:1000])

# Verificar se há UNIQUE constraint no rnc_number
if 'UNIQUE' in table_sql.upper():
    print("\n🚨 ENCONTRADO: Constraint UNIQUE na definição da tabela")
    
    # Encontrar linha com UNIQUE
    for line in table_sql.split('\n'):
        if 'rnc_number' in line.lower() and 'unique' in line.lower():
            print(f"   → {line.strip()}")

conn.close()
