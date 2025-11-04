"""
Script para SUBSTITUIR o campo 'title' pelo valor de 'description_drawing'
nas RNCs ativas onde title está igual ao description
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'ippel_system.db')

def update_titles_to_description_drawing():
    """Substitui title por description_drawing nas RNCs ativas"""
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Buscar RNCs ativas onde title está igual a description (o problema atual)
        cursor.execute("""
            SELECT id, rnc_number, title, description, description_drawing
            FROM rncs
            WHERE (is_deleted = 0 OR is_deleted IS NULL)
              AND status != 'Finalizado'
              AND title = description
              AND description_drawing IS NOT NULL
              AND TRIM(description_drawing) != ''
            ORDER BY id DESC
        """)
        
        rncs_to_update = cursor.fetchall()
        
        if not rncs_to_update:
            print("✅ Nenhuma RNC precisa ser atualizada!")
            return
        
        print(f"\n🔍 Encontradas {len(rncs_to_update)} RNCs para atualizar:\n")
        print("=" * 80)
        
        # Mostrar preview das primeiras 5
        for i, (rnc_id, rnc_number, title, description, description_drawing) in enumerate(rncs_to_update[:5], 1):
            old_preview = title[:60] + "..." if title and len(title) > 60 else (title or "[vazio]")
            new_preview = description_drawing[:60] + "..." if len(description_drawing) > 60 else description_drawing
            
            print(f"\n{i}. {rnc_number}:")
            print(f"   ❌ Title ATUAL (errado): {old_preview}")
            print(f"   ✅ Title NOVO (correto): {new_preview}")
        
        if len(rncs_to_update) > 5:
            print(f"\n... e mais {len(rncs_to_update) - 5} RNCs")
        
        print("\n" + "=" * 80)
        print(f"\n⚠️  Isso irá SUBSTITUIR o campo 'title' de {len(rncs_to_update)} RNCs.")
        print("   O título atual (descrição da não conformidade) será substituído")
        print("   pelo valor de 'description_drawing' (descrição do desenho).")
        
        response = input("\n✋ Deseja continuar? (s/n): ").strip().lower()
        
        if response != 's':
            print("\n❌ Operação cancelada!")
            return
        
        # Atualizar os títulos
        updated_count = 0
        print("\n🔄 Atualizando RNCs...")
        
        for rnc_id, rnc_number, title, description, description_drawing in rncs_to_update:
            cursor.execute("""
                UPDATE rncs
                SET title = ?
                WHERE id = ?
            """, (description_drawing, rnc_id))
            
            updated_count += 1
            
            if updated_count % 20 == 0:
                print(f"  ⏳ {updated_count}/{len(rncs_to_update)} RNCs atualizadas...")
        
        conn.commit()
        
        print(f"\n✅ SUCESSO! {updated_count} RNCs foram atualizadas!")
        print("\n📋 Verificação - Exemplos de RNCs atualizadas:")
        print("=" * 80)
        
        # Mostrar exemplos das RNCs atualizadas
        cursor.execute("""
            SELECT rnc_number, title, description_drawing
            FROM rncs
            WHERE id IN ({})
            ORDER BY id DESC
            LIMIT 5
        """.format(','.join('?' * min(5, len(rncs_to_update)))), 
        [r[0] for r in rncs_to_update[:5]])
        
        updated_examples = cursor.fetchall()
        for rnc_number, title, description_drawing in updated_examples:
            print(f"\n{rnc_number}:")
            print(f"  ✅ Title: {title}")
            print(f"  📄 Description_drawing: {description_drawing}")
            if title == description_drawing:
                print("  ✔️  CORRETO!")
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ Erro ao atualizar RNCs: {str(e)}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    print("=" * 80)
    print("🔧 ATUALIZAÇÃO: TITLE → DESCRIPTION_DRAWING")
    print("=" * 80)
    print("\nEste script irá substituir o campo 'title' pelo 'description_drawing'")
    print("nas RNCs ativas onde title está com a descrição da não conformidade.\n")
    update_titles_to_description_drawing()
    print("\n" + "=" * 80)
    print("✅ Processo concluído!")
    print("=" * 80)
