#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de teste: atualizar RNC 34769 com um número de desenho de exemplo
para verificar se aparece corretamente no dashboard
"""

import sqlite3

DB_PATH = 'ippel_system.db'

def test_update_drawing():
    """Atualiza o campo drawing da RNC 34769 para teste"""
    conn = sqlite3.connect(DB_PATH)
    conn.text_factory = str
    conn.execute('PRAGMA encoding="UTF-8"')
    cursor = conn.cursor()
    
    # Verificar estado atual
    cursor.execute('SELECT id, rnc_number, drawing FROM rncs WHERE rnc_number = "34769"')
    before = cursor.fetchone()
    
    print('=== ANTES DA ATUALIZAÇÃO ===')
    print(f'ID: {before[0]}')
    print(f'RNC: {before[1]}')
    print(f'Desenho: {repr(before[2])}')
    
    # Atualizar com número de desenho de exemplo
    test_drawing = 'P23301M7001R001'  # Usando o título como número de desenho
    cursor.execute('''
        UPDATE rncs 
        SET drawing = ?, 
            cv_desenho = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE rnc_number = "34769"
    ''', (test_drawing, test_drawing))
    
    conn.commit()
    
    # Verificar depois
    cursor.execute('SELECT id, rnc_number, drawing, cv_desenho FROM rncs WHERE rnc_number = "34769"')
    after = cursor.fetchone()
    
    print('\n=== DEPOIS DA ATUALIZAÇÃO ===')
    print(f'ID: {after[0]}')
    print(f'RNC: {after[1]}')
    print(f'Desenho: {repr(after[2])}')
    print(f'CV Desenho: {repr(after[3])}')
    
    conn.close()
    
    print('\n✅ Campo drawing atualizado com sucesso!')
    print('   Agora o desenho deve aparecer no dashboard.')

if __name__ == '__main__':
    print('Este script vai atualizar a RNC 34769 com um número de desenho de teste.')
    resposta = input('Deseja continuar? (s/n): ')
    
    if resposta.lower() == 's':
        test_update_drawing()
    else:
        print('Operação cancelada.')
