#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verificar campo drawing nas RNCs"""

import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

# Verificar RNCs com desenho preenchido
cursor.execute('''
    SELECT id, rnc_number, drawing, cv_desenho 
    FROM rncs 
    WHERE (drawing IS NOT NULL AND drawing != '') 
       OR (cv_desenho IS NOT NULL AND cv_desenho != '')
    ORDER BY id DESC 
    LIMIT 10
''')

rows = cursor.fetchall()
print('=== RNCs COM DESENHO PREENCHIDO ===')
for row in rows:
    print(f'ID {row[0]}: RNC {row[1]}')
    print(f'  drawing: {repr(row[2])}')
    print(f'  cv_desenho: {repr(row[3])}')
    print()

# Verificar todas as colunas da tabela rncs
cursor.execute('PRAGMA table_info(rncs)')
cols = cursor.fetchall()
print('\n=== TODAS AS COLUNAS DA TABELA RNCS ===')
for col in cols:
    print(f'{col[1]} ({col[2]})')

conn.close()
