"""
Script para verificar o que está sendo retornado pela API e no banco de dados
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'ippel_system.db')

def check_rnc_fields():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("\n🔍 VERIFICANDO CAMPOS DAS RNCs ATIVAS (primeiras 5):")
    print("=" * 80)
    
    cursor.execute("""
        SELECT id, rnc_number, title, description, description_drawing
        FROM rncs
        WHERE (is_deleted = 0 OR is_deleted IS NULL) 
          AND status != 'Finalizado'
        ORDER BY id DESC
        LIMIT 5
    """)
    
    rncs = cursor.fetchall()
    
    for rnc_id, rnc_number, title, description, description_drawing in rncs:
        print(f"\n📋 {rnc_number} (ID: {rnc_id})")
        print("-" * 80)
        
        title_preview = (title[:100] if title else "[NULL/VAZIO]")
        desc_preview = (description[:100] if description else "[NULL/VAZIO]")
        desc_drawing_preview = (description_drawing[:100] if description_drawing else "[NULL/VAZIO]")
        
        print(f"  📝 TITLE (campo que deveria aparecer):")
        print(f"     {title_preview}")
        print(f"\n  📄 DESCRIPTION (descrição da não conformidade - NÃO usar):")
        print(f"     {desc_preview}")
        print(f"\n  🎨 DESCRIPTION_DRAWING (descrição do desenho - usar se title vazio):")
        print(f"     {desc_drawing_preview}")
    
    conn.close()

if __name__ == "__main__":
    check_rnc_fields()
