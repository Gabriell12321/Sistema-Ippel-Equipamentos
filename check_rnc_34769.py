#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verificar RNC específica 34769"""

import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

# Buscar RNC 34769
cursor.execute('''
    SELECT id, rnc_number, title, drawing, status, is_deleted, created_at
    FROM rncs 
    WHERE rnc_number LIKE '%34769%'
''')

row = cursor.fetchone()
if row:
    print('=== RNC 34769 ===')
    print(f'ID: {row[0]}')
    print(f'Número: {row[1]}')
    print(f'Título: {row[2]}')
    print(f'Desenho: {repr(row[3])}')
    print(f'Status: {row[4]}')
    print(f'Deletado: {row[5]}')
    print(f'Criado em: {row[6]}')
else:
    print('RNC 34769 não encontrada.')
    
    # Buscar RNCs similares
    cursor.execute('''
        SELECT id, rnc_number, title, drawing, status
        FROM rncs 
        WHERE rnc_number LIKE '%347%'
        ORDER BY id DESC
        LIMIT 5
    ''')
    
    rows = cursor.fetchall()
    print('\n=== RNCs similares (347xx) ===')
    for r in rows:
        print(f'ID {r[0]}: {r[1]} - Status: {r[4]} - Desenho: {repr(r[3])}')

conn.close()
