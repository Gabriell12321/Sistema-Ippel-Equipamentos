import sqlite3

# Conectar ao banco
conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

# Ver estrutura da tabela
cursor.execute('PRAGMA table_info(rncs)')
colunas = cursor.fetchall()

print('=== COLUNAS DA TABELA rncs ===')
for c in colunas:
    if 'rnc_number' in c[1]:
        print(f'Coluna: {c[1]}')
        print(f'Tipo: {c[2]}')
        print(f'Not Null: {c[3]}')
        print(f'Default: {c[4]}')
        print(f'Primary Key: {c[5]}')

# Ver schema completo
cursor.execute('SELECT sql FROM sqlite_master WHERE type="table" AND name="rncs"')
schema = cursor.fetchone()

print('\n=== SCHEMA DA TABELA rncs ===')
if schema:
    print(schema[0])

# Ver indexes
cursor.execute('SELECT name, sql FROM sqlite_master WHERE type="index" AND tbl_name="rncs"')
indexes = cursor.fetchall()

print('\n=== INDEXES NA TABELA rncs ===')
for idx in indexes:
    print(f'Index: {idx[0]}')
    print(f'SQL: {idx[1]}')
    print()

conn.close()
