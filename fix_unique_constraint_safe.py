#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script seguro para remover UNIQUE constraint do campo rnc_number
Versão com verificações e tratamento de erros aprimorado
"""

import sqlite3
import shutil
import os
import sys
from datetime import datetime

DB_PATH = 'ippel_system.db'

def check_database_locked():
    """Verificar se o banco está sendo usado"""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=1.0)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM rncs LIMIT 1')
        conn.close()
        return False
    except sqlite3.OperationalError as e:
        if 'locked' in str(e).lower():
            return True
        raise

def check_unique_constraint_exists():
    """Verificar se a constraint UNIQUE existe"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Obter o SQL de criação da tabela
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='rncs'")
    result = cursor.fetchone()
    conn.close()
    
    if result:
        sql = result[0]
        return 'UNIQUE' in sql and 'rnc_number' in sql
    return False

def main():
    print("\n" + "="*70)
    print("VERIFICAÇÃO E REMOÇÃO DE CONSTRAINT UNIQUE")
    print("="*70 + "\n")
    
    # 1. Verificar se banco existe
    if not os.path.exists(DB_PATH):
        print(f"❌ Erro: Banco de dados '{DB_PATH}' não encontrado!")
        return False
    
    print(f"✅ Banco de dados encontrado: {DB_PATH}")
    
    # 2. Verificar se está locked
    if check_database_locked():
        print("\n❌ AVISO: O banco de dados está sendo usado por outro processo!")
        print("   Por favor, feche o servidor Flask e tente novamente.")
        print("\n   Passos:")
        print("   1. Pare o servidor Flask (Ctrl+C no terminal do servidor)")
        print("   2. Execute este script novamente")
        return False
    
    print("✅ Banco de dados disponível (não está locked)")
    
    # 3. Verificar se a constraint existe
    if not check_unique_constraint_exists():
        print("\n✅ A CONSTRAINT UNIQUE já foi removida!")
        print("   O sistema já permite números duplicados.")
        return True
    
    print("⚠️  CONSTRAINT UNIQUE encontrada - será removida\n")
    
    # 4. Criar backup
    backup_name = f'ippel_system_backup_unique_fix_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
    try:
        shutil.copy2(DB_PATH, backup_name)
        print(f"✅ Backup criado: {backup_name}")
    except Exception as e:
        print(f"❌ Erro ao criar backup: {e}")
        return False
    
    # 5. Remover constraint
    print("\n🔧 Removendo CONSTRAINT UNIQUE...\n")
    
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cursor = conn.cursor()
        
        # Desabilitar foreign keys
        cursor.execute('PRAGMA foreign_keys = OFF')
        
        # Iniciar transação
        cursor.execute('BEGIN IMMEDIATE')
        
        # Obter todas as colunas
        cursor.execute('PRAGMA table_info(rncs)')
        columns = cursor.fetchall()
        
        print(f"   📋 Total de colunas: {len(columns)}")
        
        # Criar lista de nomes de colunas
        col_names = [col[1] for col in columns]
        col_list = ', '.join(col_names)
        
        # Renomear tabela antiga
        cursor.execute('ALTER TABLE rncs RENAME TO rncs_old')
        print("   ✅ Tabela renomeada para rncs_old")
        
        # Criar nova tabela SEM UNIQUE constraint
        cursor.execute('''
            CREATE TABLE rncs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rnc_number TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                equipment TEXT,
                client TEXT,
                priority TEXT DEFAULT 'Média',
                status TEXT DEFAULT 'Pendente',
                user_id INTEGER,
                assigned_user_id INTEGER,
                is_deleted BOOLEAN DEFAULT 0,
                deleted_at TIMESTAMP,
                finalized_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                price REAL DEFAULT 0,
                disposition_usar BOOLEAN DEFAULT 0,
                disposition_retrabalhar BOOLEAN DEFAULT 0,
                disposition_rejeitar BOOLEAN DEFAULT 0,
                disposition_sucata BOOLEAN DEFAULT 0,
                disposition_devolver_estoque BOOLEAN DEFAULT 0,
                disposition_devolver_fornecedor BOOLEAN DEFAULT 0,
                inspection_aprovado BOOLEAN DEFAULT 0,
                inspection_reprovado BOOLEAN DEFAULT 0,
                inspection_ver_rnc TEXT,
                signature_inspection_date TEXT,
                signature_engineering_date TEXT,
                signature_inspection2_date TEXT,
                signature_inspection_name TEXT,
                signature_engineering_name TEXT,
                signature_inspection2_name TEXT,
                instruction_retrabalho TEXT,
                cause_rnc TEXT,
                action_rnc TEXT,
                responsavel TEXT,
                inspetor TEXT,
                setor TEXT,
                material TEXT,
                quantity TEXT,
                drawing TEXT,
                area_responsavel TEXT,
                mp TEXT,
                revision TEXT,
                position TEXT,
                cv TEXT,
                conjunto TEXT,
                modelo TEXT,
                description_drawing TEXT,
                purchase_order TEXT,
                justificativa TEXT,
                price_note TEXT,
                usuario_valorista_id INTEGER,
                cv_desenho TEXT,
                assigned_group_id INTEGER,
                causador_user_id INTEGER,
                ass_responsavel TEXT
            )
        ''')
        print("   ✅ Nova tabela criada SEM UNIQUE constraint")
        
        # Copiar dados
        cursor.execute(f'INSERT INTO rncs ({col_list}) SELECT {col_list} FROM rncs_old')
        rows_copied = cursor.rowcount
        print(f"   ✅ {rows_copied} registros copiados")
        
        # Dropar tabela antiga
        cursor.execute('DROP TABLE rncs_old')
        print("   ✅ Tabela antiga removida")
        
        # Recriar índices (exceto o UNIQUE)
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rncs_created_at ON rncs(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rncs_status ON rncs(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rncs_user ON rncs(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rncs_assigned_user ON rncs(assigned_user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rncs_client ON rncs(client)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rncs_equipment ON rncs(equipment)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rncs_priority ON rncs(priority)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rncs_is_deleted ON rncs(is_deleted)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rncs_finalized_at ON rncs(finalized_at)')
        print("   ✅ Índices recriados")
        
        # Reativar foreign keys
        cursor.execute('PRAGMA foreign_keys = ON')
        
        # Commit
        conn.commit()
        
        print("\n" + "="*70)
        print("✅ CONSTRAINT UNIQUE REMOVIDA COM SUCESSO!")
        print("⚠️  NÚMEROS DUPLICADOS AGORA SÃO PERMITIDOS")
        print("="*70)
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERRO: {e}")
        if conn:
            conn.rollback()
        return False
        
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n❌ Operação cancelada pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erro inesperado: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
