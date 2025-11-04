import sqlite3

conn = sqlite3.connect('ippel_system.db')
c = conn.cursor()

c.execute('SELECT rnc_number, description, description_drawing, title FROM rncs WHERE rnc_number IN (34893, 34894) ORDER BY rnc_number')
rows = c.fetchall()

print('CAMPOS DE DESCRIÇÃO NO BANCO:')
print('='*70)
for r in rows:
    print(f'RNC-{r[0]}:')
    print(f'  description: [{r[1][:80] if r[1] else "(vazio)"}...]')
    print(f'  description_drawing: [{r[2] if r[2] else "(vazio)"}]')
    print(f'  title: [{r[3] if r[3] else "(vazio)"}]')
    print('')

conn.close()
