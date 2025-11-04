"""
Script para verificar o estado dos campos title e description_drawing nas RNCs ativas
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'ippel_system.db')

def check_rnc_titles():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Total de RNCs ativas
    cursor.execute("""
        SELECT COUNT(*) 
        FROM rncs 
        WHERE (is_deleted = 0 OR is_deleted IS NULL) 
          AND status != 'Finalizado'
    """)
    total_active = cursor.fetchone()[0]
    
    # RNCs com title preenchido
    cursor.execute("""
        SELECT COUNT(*) 
        FROM rncs 
        WHERE (is_deleted = 0 OR is_deleted IS NULL) 
          AND status != 'Finalizado'
          AND title IS NOT NULL 
          AND TRIM(title) != ''
    """)
    with_title = cursor.fetchone()[0]
    
    # RNCs sem title mas com description_drawing
    cursor.execute("""
        SELECT COUNT(*) 
        FROM rncs 
        WHERE (is_deleted = 0 OR is_deleted IS NULL) 
          AND status != 'Finalizado'
          AND (title IS NULL OR title = '' OR TRIM(title) = '')
          AND (description_drawing IS NOT NULL AND TRIM(description_drawing) != '')
    """)
    without_title_with_desc = cursor.fetchone()[0]
    
    # RNCs sem title e sem description_drawing
    cursor.execute("""
        SELECT COUNT(*) 
        FROM rncs 
        WHERE (is_deleted = 0 OR is_deleted IS NULL) 
          AND status != 'Finalizado'
          AND (title IS NULL OR title = '' OR TRIM(title) = '')
          AND (description_drawing IS NULL OR TRIM(description_drawing) = '')
    """)
    without_both = cursor.fetchone()[0]
    
    print("\n📊 ESTATÍSTICAS DAS RNCs ATIVAS:")
    print("=" * 60)
    print(f"Total de RNCs ativas: {total_active}")
    print(f"  ✅ Com 'title' preenchido: {with_title}")
    print(f"  ⚠️  Sem 'title', mas com 'description_drawing': {without_title_with_desc}")
    print(f"  ❌ Sem 'title' e sem 'description_drawing': {without_both}")
    print("=" * 60)
    
    # Mostrar exemplos de RNCs
    print("\n📋 Exemplos de RNCs ativas (primeiras 10):")
    print("=" * 60)
    
    cursor.execute("""
        SELECT id, rnc_number, 
               CASE 
                   WHEN title IS NOT NULL AND TRIM(title) != '' THEN title
                   ELSE '[VAZIO]'
               END as title,
               CASE 
                   WHEN description_drawing IS NOT NULL AND TRIM(description_drawing) != '' THEN description_drawing
                   ELSE '[VAZIO]'
               END as description_drawing
        FROM rncs
        WHERE (is_deleted = 0 OR is_deleted IS NULL) 
          AND status != 'Finalizado'
        ORDER BY id DESC
        LIMIT 10
    """)
    
    examples = cursor.fetchall()
    for rnc_id, rnc_number, title, description_drawing in examples:
        title_preview = (title[:50] + "...") if len(title) > 50 else title
        desc_preview = (description_drawing[:50] + "...") if len(description_drawing) > 50 else description_drawing
        print(f"\n{rnc_number}:")
        print(f"  Title: {title_preview}")
        print(f"  Description: {desc_preview}")
    
    conn.close()

if __name__ == "__main__":
    check_rnc_titles()
