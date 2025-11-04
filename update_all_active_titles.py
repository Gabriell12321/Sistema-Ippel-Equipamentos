"""
Script para atualizar TODAS as RNCs ativas com description_drawing
Independente do valor atual do title
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'ippel_system.db')

def update_all_active_rncs():
    """Atualiza TODAS as RNCs ativas para usar description_drawing como título"""
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Buscar TODAS as RNCs ativas com description_drawing
        cursor.execute("""
            SELECT id, rnc_number, title, description_drawing
            FROM rncs
            WHERE (is_deleted = 0 OR is_deleted IS NULL)
              AND status != 'Finalizado'
              AND description_drawing IS NOT NULL
              AND TRIM(description_drawing) != ''
            ORDER BY id DESC
        """)
        
        rncs_to_update = cursor.fetchall()
        
        if not rncs_to_update:
            print("✅ Nenhuma RNC encontrada!")
            return
        
        print(f"\n📊 Total de RNCs ativas com description_drawing: {len(rncs_to_update)}")
        print("=" * 80)
        
        # Contar quantas já estão corretas
        already_correct = sum(1 for r in rncs_to_update if r[2] == r[3])
        need_update = len(rncs_to_update) - already_correct
        
        print(f"\n  ✅ Já corretas (title = description_drawing): {already_correct}")
        print(f"  🔄 Precisam ser atualizadas: {need_update}")
        
        if need_update == 0:
            print("\n✨ Todas as RNCs já estão corretas!")
            return
        
        print("\n" + "=" * 80)
        print("📋 Exemplos de RNCs que serão atualizadas:")
        print("=" * 80)
        
        # Mostrar apenas as que serão atualizadas
        to_show = [r for r in rncs_to_update if r[2] != r[3]][:5]
        for i, (rnc_id, rnc_number, title, description_drawing) in enumerate(to_show, 1):
            old_preview = (title[:50] + "...") if title and len(title) > 50 else (title or "[vazio]")
            new_preview = (description_drawing[:50] + "...") if len(description_drawing) > 50 else description_drawing
            
            print(f"\n{i}. {rnc_number}:")
            print(f"   ❌ Atual: {old_preview}")
            print(f"   ✅ Novo:  {new_preview}")
        
        if len(to_show) < need_update:
            print(f"\n... e mais {need_update - len(to_show)} RNCs")
        
        print("\n" + "=" * 80)
        print(f"\n⚠️  Atualizar {need_update} RNCs ativas?")
        response = input("✋ Continuar? (s/n): ").strip().lower()
        
        if response != 's':
            print("\n❌ Operação cancelada!")
            return
        
        # Atualizar apenas as que precisam
        updated_count = 0
        print("\n🔄 Atualizando...")
        
        for rnc_id, rnc_number, title, description_drawing in rncs_to_update:
            if title != description_drawing:
                cursor.execute("""
                    UPDATE rncs
                    SET title = ?
                    WHERE id = ?
                """, (description_drawing, rnc_id))
                updated_count += 1
                
                if updated_count % 20 == 0:
                    print(f"  ⏳ {updated_count}/{need_update}...")
        
        conn.commit()
        
        print(f"\n✅ SUCESSO! {updated_count} RNCs atualizadas!")
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ Erro: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

if __name__ == "__main__":
    print("=" * 80)
    print("🔧 ATUALIZAÇÃO COMPLETA: TITLE → DESCRIPTION_DRAWING")
    print("=" * 80)
    update_all_active_rncs()
    print("\n" + "=" * 80)
