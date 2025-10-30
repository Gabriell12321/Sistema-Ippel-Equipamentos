#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simular a query da API para ver o que será retornado"""

import sqlite3

conn = sqlite3.connect('ippel_system.db')
conn.text_factory = str
conn.execute('PRAGMA encoding="UTF-8"')
cursor = conn.cursor()

# Query igual à da API (routes/rnc.py linha 950)
query = '''
    SELECT 
        r.id, r.rnc_number, r.title, r.equipment, r.client, r.priority, r.status,
        r.user_id, r.assigned_user_id, r.created_at, r.updated_at, r.finalized_at,
        r.responsavel, r.setor, r.area_responsavel, 
        au.name AS assigned_user_name, 
        u.name AS user_name,
        r.cv, r.mp, r.conjunto, r.modelo, r.drawing
    FROM rncs r
    LEFT JOIN users u ON r.user_id = u.id
    LEFT JOIN users au ON r.assigned_user_id = au.id
    WHERE r.rnc_number = '34769'
'''

cursor.execute(query)
row = cursor.fetchone()

if row:
    print('=== DADOS QUE A API RETORNARÁ PARA RNC 34769 ===')
    print(f'[0] ID: {row[0]}')
    print(f'[1] RNC Number: {row[1]}')
    print(f'[2] Title: {row[2]}')
    print(f'[3] Equipment: {row[3]}')
    print(f'[4] Client: {row[4]}')
    print(f'[5] Priority: {row[5]}')
    print(f'[6] Status: {row[6]}')
    print(f'[7] User ID: {row[7]}')
    print(f'[8] Assigned User ID: {row[8]}')
    print(f'[9] Created At: {row[9]}')
    print(f'[10] Updated At: {row[10]}')
    print(f'[11] Finalized At: {row[11]}')
    print(f'[12] Responsavel: {row[12]}')
    print(f'[13] Setor: {row[13]}')
    print(f'[14] Area Responsavel: {row[14]}')
    print(f'[15] Assigned User Name: {row[15]}')
    print(f'[16] User Name: {row[16]}')
    print(f'[17] CV: {row[17]}')
    print(f'[18] MP: {row[18]}')
    print(f'[19] Conjunto: {row[19]}')
    print(f'[20] Modelo: {row[20]}')
    print(f'[21] DRAWING: {repr(row[21])} ✅')
    
    print('\n=== OBJETO JSON QUE SERÁ ENVIADO AO FRONTEND ===')
    print(f'"drawing": "{row[21]}"')

conn.close()
