#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verificar todos os campos de desenho da RNC 34769"""

import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

# Buscar todos os campos relacionados a desenho
cursor.execute('''
    SELECT id, rnc_number, drawing, cv_desenho, description_drawing, cv, title
    FROM rncs 
    WHERE rnc_number = '34769'
''')

row = cursor.fetchone()
if row:
    print('=== TODOS OS CAMPOS DE DESENHO DA RNC 34769 ===')
    print(f'ID: {row[0]}')
    print(f'RNC Number: {row[1]}')
    print(f'drawing: {repr(row[2])}')
    print(f'cv_desenho: {repr(row[3])}')
    print(f'description_drawing: {repr(row[4])}')
    print(f'cv: {repr(row[5])}')
    print(f'title: {repr(row[6])}')

conn.close()
