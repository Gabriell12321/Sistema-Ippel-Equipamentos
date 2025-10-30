#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para corrigir acentos em nomes de usuários e grupos no banco de dados.
Corrige problemas de encoding UTF-8.
"""

import sqlite3
import sys

DB_PATH = 'ippel_system.db'

# Mapeamento de correções para nomes de usuários
USER_CORRECTIONS = {
    'Alisson Mois�s': 'Alisson Moisés',
    'Alisson Moiss': 'Alisson Moisés',
    'Cl�udio Alves': 'Cláudio Alves',
    'Claudio Alves': 'Cláudio Alves',
    'Jos� Josnel Pereira dos Santos': 'José Josnel Pereira dos Santos',
    'Jose Josnel Pereira dos Santos': 'José Josnel Pereira dos Santos',
    'Jo�o Maria Carneiro': 'João Maria Carneiro',
    'Joao Maria Carneiro': 'João Maria Carneiro',
    'R�mulo Emanuel Mainardes': 'Rômulo Emanuel Mainardes',
    'Romulo Emanuel Mainardes': 'Rômulo Emanuel Mainardes',
}

# Mapeamento de correções para emails (caso necessário)
EMAIL_CORRECTIONS = {
    'alisson.moiss@ippel.com.br': 'alisson.moises@ippel.com.br',
    'cludio.alves@ippel.com.br': 'claudio.alves@ippel.com.br',
    'jos.josnel.pereira.dos.santos@ippel.com.br': 'jos.josnel.pereira.dos.santos@ippel.com.br',
    'joo.maria.carneiro@ippel.com.br': 'joo.maria.carneiro@ippel.com.br',
    'rmulo.emanuel.mainardes@ippel.com.br': 'rmulo.emanuel.mainardes@ippel.com.br',
}

# Mapeamento de correções para grupos
GROUP_CORRECTIONS = {
    'Engenharia - Ger�ncia': 'Engenharia - Gerência',
    'Engenharia - Gerncia': 'Engenharia - Gerência',
    'Produ��o': 'Produção',
    'Producao': 'Produção',
    'Produ��o - Ger�ncia': 'Produção - Gerência',
    'Producao - Gerncia': 'Produção - Gerência',
}


def fix_user_names():
    """Corrige nomes de usuários no banco de dados."""
    conn = sqlite3.connect(DB_PATH)
    conn.text_factory = str
    conn.execute('PRAGMA encoding="UTF-8"')
    cursor = conn.cursor()
    
    print("=" * 60)
    print("CORRIGINDO NOMES DE USUÁRIOS")
    print("=" * 60)
    
    # Buscar todos os usuários
    cursor.execute('SELECT id, name, email FROM users ORDER BY id')
    users = cursor.fetchall()
    
    fixed_count = 0
    for user_id, name, email in users:
        # Tentar encontrar correção pelo nome
        correct_name = None
        for wrong_name, right_name in USER_CORRECTIONS.items():
            if wrong_name.lower() in name.lower() or name.lower() in wrong_name.lower():
                correct_name = right_name
                break
        
        if correct_name and correct_name != name:
            print(f"\nUsuário ID {user_id}:")
            print(f"  Antes: {repr(name)}")
            print(f"  Depois: {repr(correct_name)}")
            
            cursor.execute('UPDATE users SET name = ? WHERE id = ?', (correct_name, user_id))
            fixed_count += 1
    
    conn.commit()
    print(f"\n✓ {fixed_count} nomes de usuários corrigidos!")
    
    conn.close()


def fix_group_names():
    """Corrige nomes de grupos no banco de dados."""
    conn = sqlite3.connect(DB_PATH)
    conn.text_factory = str
    conn.execute('PRAGMA encoding="UTF-8"')
    cursor = conn.cursor()
    
    print("\n" + "=" * 60)
    print("CORRIGINDO NOMES DE GRUPOS")
    print("=" * 60)
    
    # Buscar todos os grupos
    cursor.execute('SELECT id, name FROM groups ORDER BY id')
    groups = cursor.fetchall()
    
    fixed_count = 0
    for group_id, name in groups:
        # Tentar encontrar correção pelo nome
        correct_name = None
        for wrong_name, right_name in GROUP_CORRECTIONS.items():
            if wrong_name.lower() in name.lower() or name.lower() in wrong_name.lower():
                correct_name = right_name
                break
        
        if correct_name and correct_name != name:
            print(f"\nGrupo ID {group_id}:")
            print(f"  Antes: {repr(name)}")
            print(f"  Depois: {repr(correct_name)}")
            
            cursor.execute('UPDATE groups SET name = ? WHERE id = ?', (correct_name, group_id))
            fixed_count += 1
    
    conn.commit()
    print(f"\n✓ {fixed_count} nomes de grupos corrigidos!")
    
    conn.close()


def verify_corrections():
    """Verifica se as correções foram aplicadas."""
    conn = sqlite3.connect(DB_PATH)
    conn.text_factory = str
    conn.execute('PRAGMA encoding="UTF-8"')
    cursor = conn.cursor()
    
    print("\n" + "=" * 60)
    print("VERIFICANDO CORREÇÕES")
    print("=" * 60)
    
    print("\n--- USUÁRIOS ATUALIZADOS ---")
    cursor.execute('SELECT id, name, email FROM users ORDER BY name')
    for user_id, name, email in cursor.fetchall():
        print(f"ID {user_id}: {name} ({email})")
    
    print("\n--- GRUPOS ATUALIZADOS ---")
    cursor.execute('SELECT id, name FROM groups ORDER BY name')
    for group_id, name in cursor.fetchall():
        print(f"ID {group_id}: {name}")
    
    conn.close()


def main():
    """Função principal."""
    print("\n" + "=" * 60)
    print("CORREÇÃO DE ACENTOS NO BANCO DE DADOS")
    print("=" * 60)
    
    try:
        # Corrigir nomes de usuários
        fix_user_names()
        
        # Corrigir nomes de grupos
        fix_group_names()
        
        # Verificar correções
        verify_corrections()
        
        print("\n" + "=" * 60)
        print("✓ CORREÇÕES CONCLUÍDAS COM SUCESSO!")
        print("=" * 60 + "\n")
        
    except Exception as e:
        print(f"\n✗ ERRO: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
