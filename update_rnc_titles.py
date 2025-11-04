"""
Script para atualizar o campo 'title' das RNCs ativas
Preenche o 'title' com o valor de 'description_drawing' quando title estiver vazio
"""
import sqlite3
import os

# Caminho do banco de dados
DB_PATH = os.path.join(os.path.dirname(__file__), 'ippel_system.db')

def update_rnc_titles():
    """Atualiza os títulos das RNCs ativas que não têm título definido"""
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Buscar RNCs ativas sem título mas com description_drawing
        cursor.execute("""
            SELECT id, rnc_number, description_drawing, description
            FROM rncs
            WHERE (is_deleted = 0 OR is_deleted IS NULL)
              AND status != 'Finalizado'
              AND (title IS NULL OR title = '' OR TRIM(title) = '')
              AND (description_drawing IS NOT NULL AND TRIM(description_drawing) != '')
            ORDER BY id DESC
        """)
        
        rncs_to_update = cursor.fetchall()
        
        if not rncs_to_update:
            print("✅ Nenhuma RNC precisa ser atualizada!")
            return
        
        print(f"\n🔍 Encontradas {len(rncs_to_update)} RNCs para atualizar:\n")
        
        # Mostrar preview das atualizações
        for i, (rnc_id, rnc_number, description_drawing, description) in enumerate(rncs_to_update[:5], 1):
            preview = description_drawing[:80] + "..." if len(description_drawing) > 80 else description_drawing
            print(f"{i}. {rnc_number}: {preview}")
        
        if len(rncs_to_update) > 5:
            print(f"... e mais {len(rncs_to_update) - 5} RNCs")
        
        # Confirmar antes de atualizar
        print(f"\n⚠️  Isso irá atualizar o campo 'title' de {len(rncs_to_update)} RNCs.")
        response = input("Deseja continuar? (s/n): ").strip().lower()
        
        if response != 's':
            print("❌ Operação cancelada!")
            return
        
        # Atualizar os títulos
        updated_count = 0
        for rnc_id, rnc_number, description_drawing, description in rncs_to_update:
            # Limitar o título a 200 caracteres para manter legível
            new_title = description_drawing[:200] if len(description_drawing) > 200 else description_drawing
            
            cursor.execute("""
                UPDATE rncs
                SET title = ?
                WHERE id = ?
            """, (new_title, rnc_id))
            
            updated_count += 1
            
            if updated_count % 10 == 0:
                print(f"  ⏳ {updated_count}/{len(rncs_to_update)} RNCs atualizadas...")
        
        conn.commit()
        
        print(f"\n✅ Sucesso! {updated_count} RNCs foram atualizadas!")
        print("\n📋 Exemplos de RNCs atualizadas:")
        
        # Mostrar exemplos das RNCs atualizadas
        cursor.execute("""
            SELECT id, rnc_number, title
            FROM rncs
            WHERE id IN ({})
            LIMIT 5
        """.format(','.join('?' * len([r[0] for r in rncs_to_update[:5]]))), 
        [r[0] for r in rncs_to_update[:5]])
        
        updated_examples = cursor.fetchall()
        for rnc_id, rnc_number, title in updated_examples:
            preview = title[:80] + "..." if title and len(title) > 80 else title
            print(f"  • {rnc_number}: {preview}")
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ Erro ao atualizar RNCs: {str(e)}")
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    print("=" * 60)
    print("🔧 ATUALIZAÇÃO DE TÍTULOS DAS RNCs ATIVAS")
    print("=" * 60)
    update_rnc_titles()
    print("\n" + "=" * 60)
