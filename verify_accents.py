#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sqlite3

conn = sqlite3.connect('ippel_system.db')
conn.text_factory = str
cursor = conn.cursor()

# Buscar usuários com acentos
cursor.execute('''
    SELECT id, name, email 
    FROM users 
    WHERE name LIKE "%ã%" 
       OR name LIKE "%á%" 
       OR name LIKE "%é%" 
       OR name LIKE "%í%" 
       OR name LIKE "%ó%" 
       OR name LIKE "%ú%" 
       OR name LIKE "%ç%" 
       OR name LIKE "%â%" 
       OR name LIKE "%ê%" 
       OR name LIKE "%ô%"
       OR name LIKE "%õ%"
    ORDER BY name
''')

users = cursor.fetchall()

print('\n' + '='*80)
print('USUÁRIOS COM ACENTOS NO BANCO DE DADOS')
print('='*80)
print(f'{"ID":>4} | {"NOME":<45} | EMAIL')
print('-'*80)

for user in users:
    print(f'{user[0]:4d} | {user[1]:<45} | {user[2]}')

print('-'*80)
print(f'Total: {len(users)} usuários com acentos\n')

conn.close()
