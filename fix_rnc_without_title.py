"""
Script para atualizar RNCs que estão com "RNC sem título"
Substitui por description_drawing quando disponível
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'ippel_system.db')

def fix_rncs_without_title():
    """Atualiza RNCs com 'RNC sem título' para usar description_drawing"""
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Buscar RNCs ativas com "RNC sem título" mas com description_drawing
        cursor.execute("""
            SELECT id, rnc_number, title, description_drawing, description
            FROM rncs
            WHERE (is_deleted = 0 OR is_deleted IS NULL)
              AND status != 'Finalizado'
              AND (
                  title = 'RNC sem título' 
                  OR title IS NULL 
                  OR TRIM(title) = ''
              )
              AND description_drawing IS NOT NULL
              AND TRIM(description_drawing) != ''
            ORDER BY id DESC
        """)
        
        rncs_to_update = cursor.fetchall()
        
        if not rncs_to_update:
            print("✅ Nenhuma RNC encontrada com 'RNC sem título'!")
            
            # Verificar se há alguma ativa
            cursor.execute("SELECT COUNT(*) FROM rncs WHERE (is_deleted = 0 OR is_deleted IS NULL) AND status != 'Finalizado'")
            total = cursor.fetchone()[0]
            print(f"ℹ️  Total de RNCs ativas: {total}")
            return
        
        print(f"\n🔍 Encontradas {len(rncs_to_update)} RNCs com 'RNC sem título'")
        print("=" * 80)
        
        # Mostrar primeiros exemplos
        print("\n📋 Exemplos (primeiros 10):\n")
        for i, (rnc_id, rnc_number, title, description_drawing, description) in enumerate(rncs_to_update[:10], 1):
            desc_preview = (description_drawing[:60] + "...") if len(description_drawing) > 60 else description_drawing
            print(f"{i:2}. {rnc_number}")
            print(f"    ❌ Título atual: {title or '[NULL]'}")
            print(f"    ✅ Novo título:  {desc_preview}")
            print()
        
        if len(rncs_to_update) > 10:
            print(f"... e mais {len(rncs_to_update) - 10} RNCs\n")
        
        print("=" * 80)
        print(f"\n⚠️  Atualizar {len(rncs_to_update)} RNCs para usar 'description_drawing' como título?")
        response = input("✋ Continuar? (S/n): ").strip().lower()
        
        if response and response != 's':
            print("\n❌ Operação cancelada!")
            return
        
        # Atualizar
        updated_count = 0
        print("\n🔄 Atualizando RNCs...")
        
        for rnc_id, rnc_number, title, description_drawing, description in rncs_to_update:
            cursor.execute("""
                UPDATE rncs
                SET title = ?
                WHERE id = ?
            """, (description_drawing, rnc_id))
            
            updated_count += 1
            
            if updated_count % 20 == 0:
                print(f"  ⏳ Progresso: {updated_count}/{len(rncs_to_update)}...")
        
        conn.commit()
        
        print(f"\n✅ SUCESSO! {updated_count} RNCs foram atualizadas!")
        
        # Verificar resultado
        print("\n🔍 Verificando atualizações...")
        cursor.execute("""
            SELECT COUNT(*) 
            FROM rncs 
            WHERE (is_deleted = 0 OR is_deleted IS NULL)
              AND status != 'Finalizado'
              AND (title = 'RNC sem título' OR title IS NULL OR TRIM(title) = '')
        """)
        remaining = cursor.fetchone()[0]
        
        print(f"  📊 RNCs ativas ainda com 'RNC sem título': {remaining}")
        
        if remaining > 0:
            print(f"  ⚠️  (Essas {remaining} não têm description_drawing preenchido)")
        
        # Mostrar exemplos atualizados
        print("\n📋 Exemplos de RNCs atualizadas (primeiras 5):")
        print("=" * 80)
        
        cursor.execute("""
            SELECT rnc_number, title, description_drawing
            FROM rncs
            WHERE id IN ({})
            ORDER BY id DESC
            LIMIT 5
        """.format(','.join('?' * min(5, len(rncs_to_update)))), 
        [r[0] for r in rncs_to_update[:5]])
        
        for rnc_number, title, description_drawing in cursor.fetchall():
            print(f"\n{rnc_number}:")
            print(f"  ✅ Título: {title}")
            if title == description_drawing:
                print(f"  ✔️  CORRETO!")
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ Erro: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

if __name__ == "__main__":
    print("=" * 80)
    print("🔧 CORREÇÃO: RNCs COM 'RNC SEM TÍTULO'")
    print("=" * 80)
    print("\nEste script atualiza RNCs que estão com título vazio/nulo")
    print("para usar o valor de 'description_drawing' (descrição do desenho).\n")
    fix_rncs_without_title()
    print("\n" + "=" * 80)
    print("✅ Processo finalizado!")
    print("=" * 80)
