#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script para corrigir nomes de usuários com problemas de encoding no banco de dados
"""

import sqlite3
import sys

DB_PATH = 'ippel_system.db'

# Mapeamento de correções de nomes
CORRECTIONS = {
    # IDs com problemas de encoding detectados
    31: 'André',  # Andr�
    35: 'Aço Korte',  # A�o Korte
    36: 'Aço Corporal',  # A�o corporal
    37: 'AçoKorte',  # A�oKorte
    38: 'Açocorte',  # A�ocorte
    52: 'Cintia das Graças Kosiba',  # Cintia das Gra�as Kosiba
    56: 'Cláudio Alves',  # Cludio Alves (duplicado, corrigir)
    57: 'Cláudio Brandão',  # Cl�udio Brand�o
    59: 'Cícero Roberto Paz',  # C�cero Roberto Paz
    74: 'Edison André Ferreira Diniz',  # Edison Andr� Ferreira Diniz
    92: 'Fundição Campos Gerais',  # Fundio. Campos Gerais
    93: 'Fusão',  # Fus�o
    112: 'Jefferson Luis Gonçalves',  # Jefferson Luis Gon�alves
    115: 'José Assis',  # Jos� Assis
    116: 'José Israel',  # Jos� Israel
    117: 'José Josnei Pereira dos Santos',  # Jos� Josnei Pereira dos Santos
    118: 'José Valdemir Martins Barbosa',  # Jos� Valdemir Martins Barbosa
    120: 'João Felix',  # Jo�o Felix
    121: 'João Maria Carneiro',  # Joo.maria.carneiro (email também errado)
    122: 'João Vitor Pucci',  # Jo�o Vitor Pucci
    136: 'Luciano José Carneiro Stella',  # Luciano Jos� Carneiro Stella
    163: 'Mário Dolato Neto',  # M�rio Dolato Neto
    185: 'Rômulo Emanuel Mainardes',  # Rmulo Emanuel Mainardes
    203: 'Thiago Oliveira Guimarães',  # Thiago Oliveira Guimares
    220: 'Vinícius',  # Vincius
    221: 'Virgílio',  # Virglio
    
    # Duplicados para remover (manter apenas um)
    # Alan duplicado (IDs 1 e 4) - vamos manter ID 1 e corrigir ID 4
    # Alisson Moisés triplicado (IDs 23, 24, 25) - manter 23
    
    # Correções de nomes
    83: 'Evellyn Taianara Mello',  # Corrigir nome
    86: 'Fernando Solek',  # fernandooooooo -> Fernando Solek
}

# Emails a corrigir
EMAIL_CORRECTIONS = {
    31: 'andre2@ippel.com.br',  # Evitar conflito com ID 16
    35: 'aco.korte@ippel.com.br',
    36: 'aco.corporal@ippel.com.br',
    37: 'acokorte@ippel.com.br',
    38: 'acocorte@ippel.com.br',
    52: 'cintia.das.gracas.kosiba@ippel.com.br',
    56: 'claudio.alves2@ippel.com.br',  # ID 54 já tem claudio.alves
    57: 'claudio.brandao@ippel.com.br',
    59: 'cicero.roberto.paz@ippel.com.br',
    74: 'edison.andre.ferreira.diniz@ippel.com.br',
    92: 'fundicao.campos.gerais@ippel.com.br',
    93: 'fusao@ippel.com.br',
    112: 'jefferson.luis.goncalves@ippel.com.br',
    115: 'jose.assis@ippel.com.br',
    116: 'jose.israel@ippel.com.br',
    117: 'jose.josnei.pereira.dos.santos@ippel.com.br',
    118: 'jose.valdemir.martins.barbosa@ippel.com.br',
    120: 'joao.felix@ippel.com.br',
    121: 'joao.maria.carneiro@ippel.com.br',
    122: 'joao.vitor.pucci@ippel.com.br',
    136: 'luciano.jose.carneiro.stella@ippel.com.br',
    163: 'mario.dolato.neto@ippel.com.br',
    185: 'romulo.emanuel.mainardes@ippel.com.br',
    203: 'thiago.oliveira.guimaraes@ippel.com.br',
    220: 'vinicius2@ippel.com.br',  # ID 218 já tem vinicius
    221: 'virgilio@ippel.com.br',
    # 86: Email não será alterado pois fernando.solek já existe no ID 229
}

def fix_user_names():
    """Corrigir nomes de usuários no banco de dados"""
    try:
        conn = sqlite3.connect(DB_PATH)
        # Configurar UTF-8
        conn.text_factory = str
        conn.execute("PRAGMA encoding='UTF-8'")
        cursor = conn.cursor()
        
        print("=" * 80)
        print("CORREÇÃO DE NOMES DE USUÁRIOS")
        print("=" * 80)
        
        total_corrections = 0
        
        # Aplicar correções de nomes
        for user_id, correct_name in CORRECTIONS.items():
            cursor.execute("SELECT name FROM users WHERE id = ?", (user_id,))
            result = cursor.fetchone()
            
            if result:
                old_name = result[0]
                if old_name != correct_name:
                    print(f"\n✏️  ID {user_id:3d}: '{old_name}' → '{correct_name}'")
                    cursor.execute("UPDATE users SET name = ? WHERE id = ?", (correct_name, user_id))
                    total_corrections += 1
                else:
                    print(f"✅ ID {user_id:3d}: '{correct_name}' (já correto)")
        
        # Aplicar correções de emails
        print("\n" + "=" * 80)
        print("CORREÇÃO DE EMAILS")
        print("=" * 80)
        
        for user_id, correct_email in EMAIL_CORRECTIONS.items():
            cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
            result = cursor.fetchone()
            
            if result:
                old_email = result[0]
                if old_email != correct_email:
                    print(f"\n✏️  ID {user_id:3d}: '{old_email}' → '{correct_email}'")
                    cursor.execute("UPDATE users SET email = ? WHERE id = ?", (correct_email, user_id))
                    total_corrections += 1
                else:
                    print(f"✅ ID {user_id:3d}: '{correct_email}' (já correto)")
        
        # Commit das alterações
        conn.commit()
        
        print("\n" + "=" * 80)
        print(f"✅ TOTAL DE CORREÇÕES APLICADAS: {total_corrections}")
        print("=" * 80)
        
        # Listar usuários ainda com problemas
        print("\n" + "=" * 80)
        print("VERIFICANDO CARACTERES PROBLEMÁTICOS RESTANTES...")
        print("=" * 80)
        
        cursor.execute("SELECT id, name, email FROM users WHERE name LIKE '%�%' OR email LIKE '%�%' ORDER BY id")
        problematic = cursor.fetchall()
        
        if problematic:
            print(f"\n⚠️  Encontrados {len(problematic)} usuários com caracteres problemáticos:")
            for user in problematic:
                print(f"   ID {user[0]:3d}: {user[1]} ({user[2]})")
        else:
            print("\n✅ Nenhum caractere problemático encontrado!")
        
        conn.close()
        print("\n✅ Correções concluídas com sucesso!")
        return True
        
    except Exception as e:
        print(f"\n❌ Erro ao corrigir nomes: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = fix_user_names()
    sys.exit(0 if success else 1)
