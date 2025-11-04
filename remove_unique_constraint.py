import sqlite3
import shutil
from datetime import datetime

# Backup do banco
backup_name = f'ippel_system_backup_before_unique_removal_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
shutil.copy2('ippel_system.db', backup_name)
print(f"✅ Backup criado: {backup_name}")

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

print("\n" + "="*70)
print("REMOVENDO CONSTRAINT UNIQUE DE rnc_number")
print("="*70)

try:
    # Desabilitar foreign keys
    cursor.execute('PRAGMA foreign_keys = OFF')
    
    # Iniciar transação
    cursor.execute('BEGIN TRANSACTION')
    
    # Obter todas as colunas
    cursor.execute('PRAGMA table_info(rncs)')
    columns = cursor.fetchall()
    
    print(f"\n📋 Total de colunas: {len(columns)}")
    
    # Criar lista de nomes de colunas
    col_names = [col[1] for col in columns]
    col_list = ', '.join(col_names)
    
    print(f"📋 Colunas: {col_list[:100]}...")
    
    # Renomear tabela antiga
    cursor.execute('ALTER TABLE rncs RENAME TO rncs_old')
    print("✅ Tabela renomeada para rncs_old")
    
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
    print("✅ Nova tabela criada SEM UNIQUE constraint")
    
    # Copiar dados
    cursor.execute(f'INSERT INTO rncs ({col_list}) SELECT {col_list} FROM rncs_old')
    rows_copied = cursor.rowcount
    print(f"✅ {rows_copied} registros copiados")
    
    # Dropar tabela antiga
    cursor.execute('DROP TABLE rncs_old')
    print("✅ Tabela antiga removida")
    
    # Recriar índices (exceto o UNIQUE)
    cursor.execute('CREATE INDEX idx_rncs_created_at ON rncs(created_at)')
    cursor.execute('CREATE INDEX idx_rncs_status ON rncs(status)')
    cursor.execute('CREATE INDEX idx_rncs_user ON rncs(user_id)')
    cursor.execute('CREATE INDEX idx_rncs_assigned_user ON rncs(assigned_user_id)')
    cursor.execute('CREATE INDEX idx_rncs_client ON rncs(client)')
    cursor.execute('CREATE INDEX idx_rncs_equipment ON rncs(equipment)')
    cursor.execute('CREATE INDEX idx_rncs_priority ON rncs(priority)')
    cursor.execute('CREATE INDEX idx_rncs_is_deleted ON rncs(is_deleted)')
    cursor.execute('CREATE INDEX idx_rncs_finalized_at ON rncs(finalized_at)')
    print("✅ Índices recriados")
    
    # Reativar foreign keys
    cursor.execute('PRAGMA foreign_keys = ON')
    
    # Commit
    conn.commit()
    
    print("\n" + "="*70)
    print("✅ CONSTRAINT UNIQUE REMOVIDA COM SUCESSO!")
    print("⚠️  NÚMEROS DUPLICADOS AGORA SÃO PERMITIDOS")
    print("="*70)
    
except Exception as e:
    print(f"\n❌ ERRO: {e}")
    conn.rollback()
    raise

finally:
    conn.close()
