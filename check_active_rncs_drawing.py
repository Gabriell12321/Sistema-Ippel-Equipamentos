#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verificar RNCs ativas com desenho"""

import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

# Verificar RNCs ativas com desenho
cursor.execute('''
    SELECT id, rnc_number, title, drawing, status 
    FROM rncs 
    WHERE status != 'Finalizado' 
      AND (is_deleted = 0 OR is_deleted IS NULL)
      AND drawing IS NOT NULL
      AND drawing != ''
    ORDER BY id DESC 
    LIMIT 10
''')

rows = cursor.fetchall()
print('=== RNCs ATIVAS COM DESENHO ===')
if rows:
    for row in rows:
        print(f'ID {row[0]}: {row[1]}')
        print(f'  Título: {row[2][:50]}...' if len(row[2]) > 50 else f'  Título: {row[2]}')
        print(f'  Desenho: {repr(row[3])}')
        print(f'  Status: {row[4]}')
        print()
else:
    print('Nenhuma RNC ativa com desenho preenchido encontrada.')

conn.close()
