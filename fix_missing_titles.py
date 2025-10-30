"""
Script para corrigir RNCs sem título no banco de dados
Atualiza todos os registros com title NULL ou vazio para 'RNC sem título'
"""

import sqlite3
import os

# Caminho do banco de dados
DB_PATH = os.path.join(os.path.dirname(__file__), 'ippel_system.db')

def fix_missing_titles():
    """Atualiza todas as RNCs sem título"""
    try:
        # Conectar com timeout maior e modo WAL
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        conn.execute('PRAGMA journal_mode=WAL')
        cursor = conn.cursor()
        
        # Verificar quantas RNCs não têm título
        cursor.execute("""
            SELECT COUNT(*) 
            FROM rncs 
            WHERE title IS NULL OR TRIM(title) = ''
        """)
        count_before = cursor.fetchone()[0]
        print(f"📊 RNCs sem título encontradas: {count_before}")
        
        if count_before == 0:
            print("✅ Todas as RNCs já possuem título!")
            conn.close()
            return
        
        # Atualizar RNCs sem título
        cursor.execute("""
            UPDATE rncs 
            SET title = 'RNC sem título' 
            WHERE title IS NULL OR TRIM(title) = ''
        """)
        
        conn.commit()
        
        # Verificar se a atualização funcionou
        cursor.execute("""
            SELECT COUNT(*) 
            FROM rncs 
            WHERE title IS NULL OR TRIM(title) = ''
        """)
        count_after = cursor.fetchone()[0]
        
        updated = count_before - count_after
        print(f"✅ {updated} RNCs atualizadas com sucesso!")
        print(f"📊 RNCs sem título restantes: {count_after}")
        
        # Mostrar algumas RNCs atualizadas
        cursor.execute("""
            SELECT id, rnc_number, title 
            FROM rncs 
            WHERE title = 'RNC sem título'
            LIMIT 10
        """)
        
        updated_rncs = cursor.fetchall()
        if updated_rncs:
            print("\n📋 Exemplos de RNCs atualizadas:")
            for rnc in updated_rncs:
                print(f"   - RNC #{rnc[0]} ({rnc[1]}): {rnc[2]}")
        
        conn.close()
        print("\n✅ Correção concluída com sucesso!")
        
    except Exception as e:
        print(f"❌ Erro ao corrigir títulos: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    print("🔧 Iniciando correção de títulos...")
    print(f"📁 Banco de dados: {DB_PATH}")
    print()
    fix_missing_titles()
