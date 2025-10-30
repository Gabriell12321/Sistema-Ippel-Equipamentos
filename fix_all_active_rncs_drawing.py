#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para atualizar o campo drawing de todas as RNCs ativas
que têm o campo vazio mas têm número de desenho no título
"""

import sqlite3
import re

DB_PATH = 'ippel_system.db'

def fix_all_drawings():
    """Atualiza o campo drawing de todas as RNCs ativas"""
    conn = sqlite3.connect(DB_PATH)
    conn.text_factory = str
    conn.execute('PRAGMA encoding="UTF-8"')
    cursor = conn.cursor()
    
    # Buscar todas as RNCs ativas (não finalizadas e não deletadas)
    cursor.execute('''
        SELECT id, rnc_number, title, drawing, status
        FROM rncs 
        WHERE status != 'Finalizado'
          AND (is_deleted = 0 OR is_deleted IS NULL)
          AND (drawing IS NULL OR drawing = '')
        ORDER BY id DESC
    ''')
    
    rncs = cursor.fetchall()
    
    print('=' * 70)
    print(f'ENCONTRADAS {len(rncs)} RNCs ATIVAS SEM CAMPO DRAWING PREENCHIDO')
    print('=' * 70)
    
    updated_count = 0
    skipped_count = 0
    
    for rnc in rncs:
        rnc_id, rnc_number, title, current_drawing, status = rnc
        
        # Se o título parece ser um número de desenho (contém letras e números)
        # Exemplo: P23301M7001R001, P32407M7001A000, etc.
        if title and len(title) > 3:
            # Verificar se parece um código de desenho (letras + números)
            if re.match(r'^[A-Z0-9]+', title, re.IGNORECASE):
                print(f'\n✓ RNC-{rnc_number} (ID: {rnc_id})')
                print(f'  Status: {status}')
                print(f'  Drawing atual: {repr(current_drawing)}')
                print(f'  Title: {title}')
                print(f'  → Atualizando drawing para: {title}')
                
                # Atualizar o campo drawing com o valor do título
                cursor.execute('''
                    UPDATE rncs 
                    SET drawing = ?,
                        cv_desenho = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (title, title, rnc_id))
                
                updated_count += 1
            else:
                print(f'\n⊘ RNC-{rnc_number} (ID: {rnc_id}) - Título não parece ser desenho')
                print(f'  Title: {title}')
                skipped_count += 1
        else:
            print(f'\n⊘ RNC-{rnc_number} (ID: {rnc_id}) - Sem título ou título muito curto')
            skipped_count += 1
    
    # Commit das alterações
    conn.commit()
    
    print('\n' + '=' * 70)
    print('RESULTADO')
    print('=' * 70)
    print(f'✅ RNCs atualizadas: {updated_count}')
    print(f'⊘ RNCs ignoradas: {skipped_count}')
    print(f'📊 Total processadas: {len(rncs)}')
    
    # Verificar algumas RNCs após atualização
    if updated_count > 0:
        print('\n' + '=' * 70)
        print('VERIFICAÇÃO PÓS-ATUALIZAÇÃO (5 primeiras RNCs)')
        print('=' * 70)
        
        cursor.execute('''
            SELECT id, rnc_number, title, drawing
            FROM rncs 
            WHERE status != 'Finalizado'
              AND (is_deleted = 0 OR is_deleted IS NULL)
              AND drawing IS NOT NULL
              AND drawing != ''
            ORDER BY updated_at DESC
            LIMIT 5
        ''')
        
        verified = cursor.fetchall()
        for v in verified:
            print(f'\n✓ RNC-{v[1]} (ID: {v[0]})')
            print(f'  Title: {v[2]}')
            print(f'  Drawing: {v[3]}')
    
    conn.close()
    
    print('\n' + '=' * 70)
    print('✅ ATUALIZAÇÃO CONCLUÍDA COM SUCESSO!')
    print('=' * 70)
    print('\n💡 Dica: Limpe o cache do navegador (Ctrl+F5) para ver as mudanças.')

if __name__ == '__main__':
    print('\n' + '=' * 70)
    print('CORREÇÃO AUTOMÁTICA DE CAMPO DRAWING NAS RNCs ATIVAS')
    print('=' * 70)
    print('\nEste script vai:')
    print('1. Buscar todas as RNCs ativas sem campo drawing preenchido')
    print('2. Usar o campo title como número de desenho')
    print('3. Atualizar os campos drawing e cv_desenho')
    print('\n⚠️  ATENÇÃO: Esta operação modificará o banco de dados!')
    
    resposta = input('\nDeseja continuar? (s/n): ')
    
    if resposta.lower() == 's':
        fix_all_drawings()
    else:
        print('Operação cancelada.')
