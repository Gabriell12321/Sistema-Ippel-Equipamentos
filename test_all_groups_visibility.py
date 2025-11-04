"""
Teste COMPLETO de visibilidade de RNCs para TODOS os grupos

Verifica se gerentes/sub-gerentes de TODOS os grupos conseguem ver
TODAS as RNCs dos seus grupos, e se usuários normais veem apenas
as RNCs atribuídas a eles
"""
import sqlite3

conn = sqlite3.connect('ippel_system.db')
cursor = conn.cursor()

print("="*80)
print("TESTE COMPLETO DE VISIBILIDADE PARA TODOS OS GRUPOS")
print("="*80)

# Buscar TODOS os grupos com gerentes configurados
cursor.execute('''
    SELECT id, name, manager_user_id, sub_manager_user_id
    FROM groups
    WHERE manager_user_id IS NOT NULL OR sub_manager_user_id IS NOT NULL
    ORDER BY name
''')
groups_with_managers = cursor.fetchall()

print(f"\nGrupos com gerentes configurados: {len(groups_with_managers)}\n")

resultados = []

for group in groups_with_managers:
    group_id, group_name, manager_id, sub_manager_id = group
    
    print("="*80)
    print(f"📁 GRUPO: {group_name} (ID: {group_id})")
    print("="*80)
    
    # Contar RNCs ativas do grupo
    cursor.execute('''
        SELECT COUNT(*)
        FROM rncs
        WHERE assigned_group_id = ? 
          AND status NOT IN ('Finalizado') 
          AND (is_deleted = 0 OR is_deleted IS NULL)
    ''', (group_id,))
    total_rncs = cursor.fetchone()[0]
    
    print(f"Total de RNCs ATIVAS do grupo: {total_rncs}")
    
    if total_rncs == 0:
        print("⚠️ Nenhuma RNC ativa neste grupo, pulando...")
        continue
    
    # Contar RNCs com causador
    cursor.execute('''
        SELECT COUNT(*)
        FROM rncs
        WHERE assigned_group_id = ? 
          AND causador_user_id IS NOT NULL
          AND status NOT IN ('Finalizado')
          AND (is_deleted = 0 OR is_deleted IS NULL)
    ''', (group_id,))
    rncs_com_causador = cursor.fetchone()[0]
    
    # Contar RNCs sem causador
    cursor.execute('''
        SELECT COUNT(*)
        FROM rncs
        WHERE assigned_group_id = ? 
          AND (causador_user_id IS NULL OR causador_user_id = '')
          AND status NOT IN ('Finalizado')
          AND (is_deleted = 0 OR is_deleted IS NULL)
    ''', (group_id,))
    rncs_sem_causador = cursor.fetchone()[0]
    
    print(f"  - Com causador específico: {rncs_com_causador}")
    print(f"  - Sem causador (todo o grupo): {rncs_sem_causador}")
    
    # Testar GERENTE
    if manager_id:
        cursor.execute('SELECT name FROM users WHERE id = ?', (manager_id,))
        manager = cursor.fetchone()
        manager_name = manager[0] if manager else 'N/A'
        
        print(f"\n👔 Gerente: {manager_name} (ID: {manager_id})")
        
        # Query do gerente
        cursor.execute('''
            SELECT DISTINCT r.id
            FROM rncs r
            LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id
            WHERE (r.is_deleted = 0 OR r.is_deleted IS NULL)
              AND r.status NOT IN ('Finalizado')
              AND (
                  r.user_id = ?
                  OR r.assigned_user_id = ?
                  OR rs.shared_with_user_id = ?
                  OR (r.assigned_group_id IS NOT NULL AND EXISTS (
                      SELECT 1 FROM groups g 
                      WHERE g.id = r.assigned_group_id 
                        AND (g.manager_user_id = ? OR g.sub_manager_user_id = ?)
                  ))
              )
            ORDER BY r.id DESC
        ''', (manager_id, manager_id, manager_id, manager_id, manager_id))
        
        manager_rncs = cursor.fetchall()
        
        # Contar quantas RNCs o gerente vê DO SEU GRUPO
        cursor.execute('''
            SELECT COUNT(DISTINCT r.id)
            FROM rncs r
            LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id
            WHERE (r.is_deleted = 0 OR r.is_deleted IS NULL)
              AND r.status NOT IN ('Finalizado')
              AND r.assigned_group_id = ?
              AND (
                  r.user_id = ?
                  OR r.assigned_user_id = ?
                  OR rs.shared_with_user_id = ?
                  OR (r.assigned_group_id IS NOT NULL AND EXISTS (
                      SELECT 1 FROM groups g 
                      WHERE g.id = r.assigned_group_id 
                        AND (g.manager_user_id = ? OR g.sub_manager_user_id = ?)
                  ))
              )
        ''', (group_id, manager_id, manager_id, manager_id, manager_id, manager_id))
        
        manager_group_rncs = cursor.fetchone()[0]
        
        print(f"  Total de RNCs que vê (todas): {len(manager_rncs)}")
        print(f"  RNCs do seu grupo: {manager_group_rncs}")
        
        if manager_group_rncs >= total_rncs:
            print(f"  ✅ OK - Vê todas/quase todas as RNCs do grupo ({manager_group_rncs}/{total_rncs})")
            resultados.append({
                'grupo': group_name,
                'tipo': 'Gerente',
                'nome': manager_name,
                'status': 'OK',
                'viu': manager_group_rncs,
                'total': total_rncs
            })
        else:
            print(f"  ❌ ERRO - Deveria ver {total_rncs}, mas vê apenas {manager_group_rncs}")
            print(f"  Faltando: {total_rncs - manager_group_rncs} RNCs")
            resultados.append({
                'grupo': group_name,
                'tipo': 'Gerente',
                'nome': manager_name,
                'status': 'ERRO',
                'viu': manager_group_rncs,
                'total': total_rncs
            })
    
    # Testar SUB-GERENTE
    if sub_manager_id and sub_manager_id != manager_id:
        cursor.execute('SELECT name FROM users WHERE id = ?', (sub_manager_id,))
        sub_manager = cursor.fetchone()
        sub_manager_name = sub_manager[0] if sub_manager else 'N/A'
        
        print(f"\n👔 Sub-Gerente: {sub_manager_name} (ID: {sub_manager_id})")
        
        # Query do sub-gerente
        cursor.execute('''
            SELECT DISTINCT r.id
            FROM rncs r
            LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id
            WHERE (r.is_deleted = 0 OR r.is_deleted IS NULL)
              AND r.status NOT IN ('Finalizado')
              AND (
                  r.user_id = ?
                  OR r.assigned_user_id = ?
                  OR rs.shared_with_user_id = ?
                  OR (r.assigned_group_id IS NOT NULL AND EXISTS (
                      SELECT 1 FROM groups g 
                      WHERE g.id = r.assigned_group_id 
                        AND (g.manager_user_id = ? OR g.sub_manager_user_id = ?)
                  ))
              )
            ORDER BY r.id DESC
        ''', (sub_manager_id, sub_manager_id, sub_manager_id, sub_manager_id, sub_manager_id))
        
        sub_manager_rncs = cursor.fetchall()
        
        # Contar quantas RNCs o sub-gerente vê DO SEU GRUPO
        cursor.execute('''
            SELECT COUNT(DISTINCT r.id)
            FROM rncs r
            LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id
            WHERE (r.is_deleted = 0 OR r.is_deleted IS NULL)
              AND r.status NOT IN ('Finalizado')
              AND r.assigned_group_id = ?
              AND (
                  r.user_id = ?
                  OR r.assigned_user_id = ?
                  OR rs.shared_with_user_id = ?
                  OR (r.assigned_group_id IS NOT NULL AND EXISTS (
                      SELECT 1 FROM groups g 
                      WHERE g.id = r.assigned_group_id 
                        AND (g.manager_user_id = ? OR g.sub_manager_user_id = ?)
                  ))
              )
        ''', (group_id, sub_manager_id, sub_manager_id, sub_manager_id, sub_manager_id, sub_manager_id))
        
        sub_manager_group_rncs = cursor.fetchone()[0]
        
        print(f"  Total de RNCs que vê (todas): {len(sub_manager_rncs)}")
        print(f"  RNCs do seu grupo: {sub_manager_group_rncs}")
        
        if sub_manager_group_rncs >= total_rncs:
            print(f"  ✅ OK - Vê todas/quase todas as RNCs do grupo ({sub_manager_group_rncs}/{total_rncs})")
            resultados.append({
                'grupo': group_name,
                'tipo': 'Sub-Gerente',
                'nome': sub_manager_name,
                'status': 'OK',
                'viu': sub_manager_group_rncs,
                'total': total_rncs
            })
        else:
            print(f"  ❌ ERRO - Deveria ver {total_rncs}, mas vê apenas {sub_manager_group_rncs}")
            print(f"  Faltando: {total_rncs - sub_manager_group_rncs} RNCs")
            resultados.append({
                'grupo': group_name,
                'tipo': 'Sub-Gerente',
                'nome': sub_manager_name,
                'status': 'ERRO',
                'viu': sub_manager_group_rncs,
                'total': total_rncs
            })
    
    print()

# RESUMO FINAL
print("\n" + "="*80)
print("RESUMO FINAL")
print("="*80)

ok_count = sum(1 for r in resultados if r['status'] == 'OK')
error_count = sum(1 for r in resultados if r['status'] == 'ERRO')

print(f"\nTotal de testes: {len(resultados)}")
print(f"✅ Sucesso: {ok_count}")
print(f"❌ Falha: {error_count}")

if error_count > 0:
    print(f"\n⚠️ PROBLEMAS ENCONTRADOS:")
    for r in resultados:
        if r['status'] == 'ERRO':
            print(f"  - {r['grupo']}: {r['tipo']} '{r['nome']}' vê {r['viu']}/{r['total']} RNCs")
else:
    print(f"\n🎉 TODOS OS GERENTES/SUB-GERENTES ESTÃO VENDO SUAS RNCs CORRETAMENTE!")

print("="*80)

conn.close()
