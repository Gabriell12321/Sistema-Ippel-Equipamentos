import logging
import sqlite3
import json
import threading
from datetime import datetime
from flask import Blueprint, request, jsonify, render_template, redirect, session, current_app

# Local DB path to avoid early circular imports
DB_PATH = 'ippel_system.db'
DATABASE_PATH = 'ippel_system.db'  # Alias para compatibilidade

rnc = Blueprint('rnc', __name__)

# Limite padrão para endpoints do RNC (se limiter ativo)
try:
    import importlib
    _rl = importlib.import_module('services.rate_limit')
    _limiter = getattr(_rl, 'limiter')()
    if _limiter is not None:
        _limiter.limit("180 per minute")(rnc)
except Exception:
    pass
# Proteções avançadas (CSRF/Permissões) com fallback seguro
try:
    import importlib as _importlib_ep
    _ep = _importlib_ep.import_module('services.endpoint_protection')
    csrf_protect = getattr(_ep, 'csrf_protect')
    require_permission = getattr(_ep, 'require_permission')
except Exception:
    def csrf_protect(*_a, **_k):
        def _d(f):
            return f
        return _d
    def require_permission(*_a, **_k):
        def _d(f):
            return f
        return _d
logger = logging.getLogger('ippel.rnc')


@rnc.route('/api/rnc/next-number', methods=['GET'])
def get_next_rnc_number():
    """Endpoint para obter o próximo número de RNC disponível"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Gerar número sequencial de RNC (começando em 34870)
        BASE_NUMBER = 34729  # Base original para buscar todas as RNCs
        MIN_NUMBER = 34870  # Número mínimo a ser usado nas próximas RNCs
        
        # Buscar o MAIOR número já usado (incluindo finalizadas e ativas)
        cursor.execute("""
            SELECT rnc_number FROM rncs 
            WHERE rnc_number GLOB '[0-9]*'
            AND CAST(rnc_number AS INTEGER) >= ?
            ORDER BY CAST(rnc_number AS INTEGER) DESC 
            LIMIT 1
        """, (BASE_NUMBER,))
        
        last_rnc = cursor.fetchone()
        
        if last_rnc:
            try:
                last_number = int(last_rnc[0])
                next_number = last_number + 1
                # Garantir que o próximo número seja no mínimo MIN_NUMBER
                if next_number < MIN_NUMBER:
                    next_number = MIN_NUMBER
                logger.info(f"Último número encontrado: {last_number}, próximo será: {next_number}")
            except ValueError:
                next_number = MIN_NUMBER
                logger.warning(f"Erro ao converter último número, usando número mínimo: {MIN_NUMBER}")
        else:
            next_number = MIN_NUMBER
            logger.info(f"Nenhum número anterior encontrado, começando em: {MIN_NUMBER}")
        
        conn.close()
        
        return jsonify({
            'success': True,
            'next_number': str(next_number)
        })
        
    except Exception as e:
        logger.error(f"Erro ao gerar próximo número RNC: {e}")
        return jsonify({
            'success': False,
            'message': f'Erro ao gerar número: {str(e)}'
        }), 500


@rnc.route('/api/rnc/<int:rnc_id>/renumber', methods=['POST', 'OPTIONS'])
# CSRF desabilitado para permitir AJAX com credentials na porta 5001
# @csrf_protect()
def renumber_rnc(rnc_id):
    """Endpoint para renumerar uma RNC (somente admin)"""
    logger.info(f"🔢 Renumber request - RNC ID: {rnc_id}, Method: {request.method}, Session: {session.get('user_id', 'NONE')}")
    
    # Suporte a preflight CORS
    if request.method == 'OPTIONS':
        return jsonify({'success': True}), 200
    
    if 'user_id' not in session:
        logger.warning(f"❌ Renumber NEGADO - Sem sessão para RNC {rnc_id}")
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    
    try:
        from services.permissions import has_permission
        from services.cache import clear_rnc_cache
        
        # Verificar se é admin
        if not has_permission(session['user_id'], 'admin_access'):
            return jsonify({
                'success': False,
                'message': 'Acesso negado: apenas administradores podem renumerar RNCs'
            }), 403
        
        data = request.get_json() or {}
        new_number = data.get('new_number')
        
        if not new_number:
            return jsonify({'success': False, 'message': 'Número novo não fornecido'}), 400
        
        # Validar formato do número (apenas dígitos)
        if not str(new_number).isdigit():
            return jsonify({'success': False, 'message': 'Número deve conter apenas dígitos'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verificar se a RNC existe
        cursor.execute('SELECT rnc_number, status FROM rncs WHERE id = ?', (rnc_id,))
        rnc_data = cursor.fetchone()
        
        if not rnc_data:
            conn.close()
            return jsonify({'success': False, 'message': 'RNC não encontrada'}), 404
        
        old_number = rnc_data[0]
        status = rnc_data[1]
        
        # Verificar se o novo número já existe
        cursor.execute('SELECT id FROM rncs WHERE rnc_number = ? AND id != ?', (str(new_number), rnc_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({
                'success': False,
                'message': f'O número {new_number} já está em uso por outra RNC'
            }), 400
        
        # Atualizar o número
        cursor.execute('UPDATE rncs SET rnc_number = ? WHERE id = ?', (str(new_number), rnc_id))
        conn.commit()
        conn.close()
        
        # Limpar cache
        clear_rnc_cache()
        
        logger.info(f"✅ RNC {rnc_id} renumerada: {old_number} → {new_number} por usuário {session['user_id']}")
        
        return jsonify({
            'success': True,
            'message': f'RNC renumerada com sucesso: {old_number} → {new_number}',
            'old_number': old_number,
            'new_number': new_number
        })
        
    except Exception as e:
        logger.error(f"Erro ao renumerar RNC {rnc_id}: {e}")
        return jsonify({
            'success': False,
            'message': f'Erro ao renumerar RNC: {str(e)}'
        }), 500


@rnc.route('/api/rnc/create', methods=['POST'])
@csrf_protect()
def create_rnc():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401

    try:
        from services.permissions import has_permission
        from services.cache import clear_rnc_cache
        from services.groups import get_users_by_group
        from services.rnc import share_rnc_with_user
        from routes.field_locks import get_user_locked_fields
        data = request.get_json() or {}

        # Validar campos bloqueados
        locked_fields = get_user_locked_fields(session['user_id'])
        if locked_fields:
            attempted_fields = []
            for field in locked_fields:
                if field in data and data[field] is not None:
                    # Considerar valores vazios (incluindo datas vazias como "///", "//", "/", etc.)
                    field_value = str(data[field]).strip()
                    is_empty_date = field_value.replace('/', '').strip() == ''
                    
                    if field_value != '' and not is_empty_date:
                        attempted_fields.append(field)
            
            if attempted_fields:
                return jsonify({
                    'success': False,
                    'message': f'Os seguintes campos estão bloqueados para seu grupo: {", ".join(attempted_fields)}'
                }), 403

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(rncs)")
        cols = {row[1] for row in cursor.fetchall()}

        # Gerar número sequencial de RNC (começando em 34870) - ATUALIZADO
        BASE_NUMBER = 34729  # Base original para buscar todas as RNCs
        MIN_NUMBER = 34870  # Número mínimo a ser usado nas próximas RNCs (FORÇADO)
        
        # Buscar o MAIOR número já usado (incluindo finalizadas e ativas)
        cursor.execute("""
            SELECT rnc_number FROM rncs 
            WHERE rnc_number GLOB '[0-9]*'
            AND CAST(rnc_number AS INTEGER) >= ?
            ORDER BY CAST(rnc_number AS INTEGER) DESC 
            LIMIT 1
        """, (BASE_NUMBER,))
        
        last_rnc = cursor.fetchone()
        
        if last_rnc:
            # Pegar o último número e incrementar
            try:
                last_number = int(last_rnc[0])
                next_number = last_number + 1
                # Garantir que o próximo número seja no mínimo MIN_NUMBER
                if next_number < MIN_NUMBER:
                    next_number = MIN_NUMBER
                logger.info(f"Último número encontrado: {last_number}, próximo será: {next_number}")
            except ValueError:
                # Se falhar, usar MIN_NUMBER
                next_number = MIN_NUMBER
                logger.warning(f"Erro ao converter último número, usando número mínimo: {MIN_NUMBER}")
        else:
            # Nenhum número encontrado, começar do MIN_NUMBER
            next_number = MIN_NUMBER
            logger.info(f"Nenhum número anterior encontrado, começando em: {MIN_NUMBER}")
        
        rnc_number = f"{next_number}"
        logger.info(f" Gerando RNC com número: {rnc_number}")

        signature_columns = {
            'signature_inspection_name',
            'signature_engineering_name',
            'signature_inspection2_name'
        }
        if signature_columns & cols:
            assinaturas = [
                data.get('signature_inspection_name', data.get('assinatura1', '')),
                data.get('signature_engineering_name', data.get('assinatura2', '')),
                data.get('signature_inspection2_name', data.get('assinatura3', '')),
            ]
            if not any(a and a != 'NOME' for a in assinaturas):
                return jsonify({'success': False, 'message': 'É obrigatório preencher pelo menos uma assinatura!'}), 400

        cursor.execute('SELECT department FROM users WHERE id = ?', (session['user_id'],))
        user_dept_row = cursor.fetchone()
        user_department = user_dept_row[0] if user_dept_row else 'N/A'

        values_by_col = {
            'rnc_number': rnc_number,
            'title': data.get('title') or data.get('description', '')[:100] or 'RNC sem título',
            'description': data.get('description', ''),
            'equipment': data.get('equipment', ''),
            'client': data.get('client', ''),
            'priority': data.get('priority', 'Média'),
            'status': 'Pendente',
            'user_id': session['user_id'],
            'assigned_user_id': data.get('assigned_user_id'),
            'department': user_department,
            'signature_inspection_name': data.get('signature_inspection_name', data.get('assinatura1', '')),
            'signature_engineering_name': data.get('signature_engineering_name', data.get('assinatura2', '')),
            'signature_inspection2_name': data.get('signature_inspection2_name', data.get('assinatura3', '')),
            'signature_inspection_date': data.get('signature_inspection_date', ''),
            'signature_engineering_date': data.get('signature_engineering_date', ''),
            'signature_inspection2_date': data.get('signature_inspection2_date', ''),
            'price': float(data.get('price') or 0),
            # Campos adicionais do formulário (persistem somente se existirem na tabela)
            'conjunto': data.get('conjunto', ''),
            'modelo': data.get('modelo', ''),
            'description_drawing': data.get('description_drawing', ''),
            'quantity': data.get('quantity', 0),
            'material': data.get('material', ''),
            'purchase_order': data.get('purchase_order', ''),
            'responsavel': data.get('responsavel') or data.get('nome_responsavel', ''),
            'inspetor': data.get('inspetor', ''),
            'area_responsavel': data.get('area_responsavel', ''),
            'ass_responsavel': data.get('ass_responsavel', ''),
            'setor': data.get('setor', ''),
            'mp': data.get('mp', ''),
            'revision': data.get('revision', ''),
            'position': data.get('position', ''),
            'cv': data.get('cv', ''),
            'drawing': data.get('drawing', ''),
            'price_note': data.get('price_note', ''),
            'disposition_usar': int(data.get('disposition_usar', False)),
            'disposition_retrabalhar': int(data.get('disposition_retrabalhar', False)),
            'disposition_rejeitar': int(data.get('disposition_rejeitar', False)),
            'disposition_sucata': int(data.get('disposition_sucata', False)),
            'disposition_devolver_estoque': int(data.get('disposition_devolver_estoque', False)),
            'disposition_devolver_fornecedor': int(data.get('disposition_devolver_fornecedor', False)),
            'inspection_aprovado': int(data.get('inspection_aprovado', False)),
            'inspection_reprovado': int(data.get('inspection_reprovado', False)),
            'inspection_ver_rnc': data.get('inspection_ver_rnc', ''),
            'instruction_retrabalho': data.get('instruction_retrabalho', ''),
            'cause_rnc': data.get('cause_rnc', ''),
            'action_rnc': data.get('action_rnc', ''),
        }

        insert_cols = [c for c in values_by_col.keys() if c in cols]
        insert_vals = [values_by_col[c] for c in insert_cols]

        if not insert_cols:
            conn.close()
            return jsonify({'success': False, 'message': 'Schema da tabela rncs inválido'}), 500

        placeholders = ", ".join(["?"] * len(insert_cols))
        sql = f"INSERT INTO rncs ({', '.join(insert_cols)}) VALUES ({placeholders})"
        cursor.execute('BEGIN IMMEDIATE')
        cursor.execute(sql, insert_vals)
        rnc_id = cursor.lastrowid

        shared_group_ids = data.get('shared_group_ids', []) or []

        try:
            def _share_task(rid, owner_id, group_ids):
                for gid in group_ids or []:
                    if not gid:
                        continue
                    users = get_users_by_group(gid)
                    for u in users:
                        uid = u[0]
                        if uid != owner_id:
                            share_rnc_with_user(rid, owner_id, uid, 'view')
            threading.Thread(target=_share_task, args=(rnc_id, session['user_id'], shared_group_ids), daemon=True).start()
        except Exception as e:
            logger.warning(f"Agendamento de compartilhamento falhou: {e}")

        # Salvar itens de valores/hora se fornecidos
        valores_itens = data.get('valores_itens', [])
        if valores_itens and len(valores_itens) > 0:
            try:
                for item in valores_itens:
                    cursor.execute('''
                        INSERT INTO rnc_valores_itens 
                        (rnc_id, codigo, descricao, setor, valor_hora, horas, subtotal)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        rnc_id,
                        item.get('codigo', ''),
                        item.get('descricao', ''),
                        item.get('setor', ''),
                        float(item.get('valor_hora', 0)),
                        float(item.get('horas', 0)),
                        float(item.get('subtotal', 0))
                    ))
                logger.info(f" Salvos {len(valores_itens)} itens de valores para RNC {rnc_id}")
            except Exception as e:
                logger.error(f" Erro ao salvar itens de valores: {e}")
        
        # ============================================
        # ATRIBUIÇÃO DE RNC (Grupo Completo ou Usuários Específicos)
        # ============================================
        assign_to_all_group = data.get('assign_to_all_group', False)
        assigned_group_id = data.get('assigned_group_id')
        assigned_user_ids = data.get('assigned_user_ids', [])
        causador_user_id = data.get('causador_user_id')
        
        # Validar e limpar causador_user_id (pode vir como string vazia, None, ou "")
        if causador_user_id:
            causador_user_id = str(causador_user_id).strip()
            if not causador_user_id or causador_user_id == '' or causador_user_id == 'null' or causador_user_id == 'undefined':
                causador_user_id = None
            else:
                try:
                    causador_user_id = int(causador_user_id)
                except (ValueError, TypeError):
                    causador_user_id = None
        
        logger.info(f" DADOS DE ATRIBUIÇÃO RECEBIDOS:")
        logger.info(f"  - causador_user_id: {causador_user_id} (tipo: {type(causador_user_id)})")
        logger.info(f"  - assigned_group_id: {assigned_group_id}")
        logger.info(f"  - assign_to_all_group: {assign_to_all_group}")
        logger.info(f"  - area_responsavel: {data.get('area_responsavel')}")
        
        # Se não há assigned_group_id mas há shared_group_ids, usar o primeiro grupo compartilhado
        if not assigned_group_id and shared_group_ids and len(shared_group_ids) > 0:
            assigned_group_id = shared_group_ids[0]
            logger.info(f" Convertendo shared_group_ids para assigned_group_id: {assigned_group_id}")
        
        # Se não há assigned_group_id mas há area_responsavel (ID do grupo), usar o area_responsavel
        if not assigned_group_id and data.get('area_responsavel'):
                raw_area = data.get('area_responsavel')
                # Primeiro, tentar interpretar como ID numérico
                try:
                    area_responsavel_id = int(raw_area)
                    assigned_group_id = area_responsavel_id
                    logger.info(f" Convertendo area_responsavel (id) para assigned_group_id: {assigned_group_id}")
                except (ValueError, TypeError):
                    # Se não for numérico, procurar por um grupo com esse nome (case-insensitive)
                    try:
                        name = str(raw_area).strip()
                        if name:
                            # Busca exata por nome (case-insensitive)
                            cursor.execute('SELECT id FROM groups WHERE lower(name) = lower(?) LIMIT 1', (name,))
                            row = cursor.fetchone()
                            if not row:
                                # Busca por contém (como fallback)
                                cursor.execute('SELECT id FROM groups WHERE lower(name) LIKE lower(?) LIMIT 1', (f'%{name}%',))
                                row = cursor.fetchone()
                            if row:
                                assigned_group_id = int(row[0])
                                logger.info(f" Resolveu area_responsavel '{name}' para assigned_group_id: {assigned_group_id}")
                            else:
                                logger.warning(f" Nenhum grupo encontrado com o nome area_responsavel='{name}'")
                    except Exception as e:
                        logger.warning(f" Erro ao resolver area_responsavel para grupo: {e}")
        
        # Log dos dados recebidos para debug
        logger.info(f" Dados recebidos - area_responsavel: {data.get('area_responsavel')}, shared_group_ids: {shared_group_ids}, assigned_group_id: {assigned_group_id}, causador_user_id: {causador_user_id}")

        # Se resolvemos um assigned_group_id, validar que o grupo realmente existe
        if assigned_group_id:
            try:
                cursor.execute('SELECT 1 FROM groups WHERE id = ? LIMIT 1', (int(assigned_group_id),))
                if not cursor.fetchone():
                    logger.warning(f" assigned_group_id resolvido ({assigned_group_id}) não existe em groups; ignorando")
                    assigned_group_id = None
            except Exception as e:
                logger.warning(f" Erro ao validar assigned_group_id: {e}")
        
        # LÓGICA DE ATRIBUIÇÃO:
        # 1. Se Nome Causador está vazio E tem setor selecionado → Atribuir para TODO o setor
        # 2. Se Nome Causador preenchido → Atribuir para o usuário causador + gerentes do setor
        
        # Verificar se usuário tem permissão para atribuir RNC ao grupo
        can_assign_to_group = has_permission(session['user_id'], 'assign_rnc_to_group')
        
        # Permitir atribuição se o usuário está atribuindo para seu próprio grupo
        user_own_group = False
        if assigned_group_id:
            cursor.execute('SELECT group_id FROM users WHERE id = ?', (session['user_id'],))
            user_group_row = cursor.fetchone()
            if user_group_row and user_group_row[0] == int(assigned_group_id):
                user_own_group = True
                logger.info(f" Usuário está atribuindo RNC para seu próprio grupo: {assigned_group_id}")
        
        # Permitir atribuição se há area_responsavel definida (setor selecionado)
        has_area_responsavel = bool(data.get('area_responsavel'))
        
        # Determinar se deve atribuir para todo o grupo baseado na presença do causador
        # INICIALIZAR assign_to_all_group SEMPRE
        assign_to_all_group = False  # Default: não atribuir para todo o grupo
        
        logger.info(f"=" * 80)
        logger.info(f"DECISÃO DE ATRIBUIÇÃO:")
        logger.info(f"  causador_user_id = {causador_user_id} (tipo: {type(causador_user_id)})")
        logger.info(f"  has_area_responsavel = {has_area_responsavel}")
        logger.info(f"  assigned_group_id = {assigned_group_id}")
        
        if causador_user_id:
            # Nome Causador preenchido → Atribuir apenas para o causador + gerentes
            assign_to_all_group = False
            logger.info(f"✓ DECISÃO: Nome Causador preenchido (ID: {causador_user_id})")
            logger.info(f"  → assign_to_all_group = False")
            logger.info(f"  → Atribuir para: Causador + Gerentes + Ronaldo")
        elif has_area_responsavel:
            # Nome Causador vazio E setor selecionado → Atribuir para todo o grupo
            assign_to_all_group = True
            logger.info(f"✓ DECISÃO: Nome Causador VAZIO e setor selecionado")
            logger.info(f"  → assign_to_all_group = True")
            logger.info(f"  → Atribuir para: TODO O GRUPO")
        else:
            logger.info(f"⚠️ DECISÃO: Nenhuma condição atendida!")
            logger.info(f"  → assign_to_all_group = {assign_to_all_group}")
        
        logger.info(f"=" * 80)
        
        logger.info(f" Verificação de permissão - assign_to_all_group: {assign_to_all_group}, assigned_group_id: {assigned_group_id}, can_assign_to_group: {can_assign_to_group}, user_own_group: {user_own_group}, has_area_responsavel: {has_area_responsavel}")
        
        logger.info(f"\n{'='*80}")
        logger.info(f"VERIFICANDO QUAL BLOCO VAI EXECUTAR:")
        
        # Primeira condição
        condicao1 = assign_to_all_group and assigned_group_id and (can_assign_to_group or user_own_group or has_area_responsavel)
        logger.info(f"\n1️⃣ BLOCO MODO 1 (TODO O GRUPO):")
        logger.info(f"  Condição: assign_to_all_group ({assign_to_all_group}) AND assigned_group_id ({assigned_group_id}) AND (...)")
        logger.info(f"  Resultado: {condicao1}")
        
        if condicao1:
            logger.info(f"  ✓ VAI EXECUTAR ESTE BLOCO")
            # MODO 1: Atribuir para TODO O GRUPO (Nome Causador vazio)
            try:
                # Salvar o grupo atribuído na própria RNC (para controle de visibilidade)
                cursor.execute('''
                    UPDATE rncs SET assigned_group_id = ? WHERE id = ?
                ''', (assigned_group_id, rnc_id))
                
                # Buscar todos os usuários do grupo
                users_in_group = get_users_by_group(assigned_group_id)
                
                # Compartilhar RNC com todos os usuários do grupo
                for user in users_in_group:
                    user_id = user[0]
                    if user_id != session['user_id']:
                        cursor.execute('''
                            INSERT INTO rnc_shares 
                            (rnc_id, shared_by_user_id, shared_with_user_id, permission_level)
                            VALUES (?, ?, ?, 'assigned')
                        ''', (rnc_id, session['user_id'], user_id))
                
                logger.info(f" RNC {rnc_id} atribuída para TODO O GRUPO {assigned_group_id} ({len(users_in_group)} usuários)")
            except Exception as e:
                logger.error(f" Erro ao atribuir RNC ao grupo: {e}")
        else:
            logger.info(f"  ✗ NÃO VAI EXECUTAR ESTE BLOCO")
        
        # Segunda condição
        condicao2 = causador_user_id and assigned_group_id
        logger.info(f"\n2️⃣ BLOCO MODO 2 (CAUSADOR + GERENTES):")
        logger.info(f"  Condição: causador_user_id ({causador_user_id}) AND assigned_group_id ({assigned_group_id})")
        logger.info(f"  Resultado: {condicao2}")
        
        if condicao2:
            logger.info(f"  ✓ VAI EXECUTAR ESTE BLOCO")
            # MODO 2: Atribuir para USUÁRIO CAUSADOR + GERENTES (Nome Causador preenchido)
            try:
                # Salvar o grupo atribuído na RNC
                cursor.execute('''
                    UPDATE rncs SET assigned_group_id = ?, causador_user_id = ? WHERE id = ?
                ''', (assigned_group_id, int(causador_user_id), rnc_id))
                
                # Buscar gerentes do grupo definidos no banco de dados
                cursor.execute('''
                    SELECT manager_user_id, sub_manager_user_id
                    FROM groups
                    WHERE id = ?
                ''', (assigned_group_id,))
                group_managers = cursor.fetchone()
                
                # Lista de usuários para compartilhar: causador + gerentes
                users_to_share = [int(causador_user_id)]
                gerentes_encontrados = 0
                
                if group_managers:
                    manager_id = group_managers[0]
                    sub_manager_id = group_managers[1]
                    
                    if manager_id and manager_id not in users_to_share and manager_id != session['user_id']:
                        users_to_share.append(manager_id)
                        gerentes_encontrados += 1
                        logger.info(f"  Gerente principal adicionado: ID {manager_id}")
                    
                    if sub_manager_id and sub_manager_id not in users_to_share and sub_manager_id != session['user_id']:
                        users_to_share.append(sub_manager_id)
                        gerentes_encontrados += 1
                        logger.info(f"  Sub-gerente adicionado: ID {sub_manager_id}")
                
                if gerentes_encontrados == 0:
                    logger.warning(f"  Nenhum gerente definido no banco para o grupo {assigned_group_id}. Configure gerentes em /admin/managers")
                
                # Compartilhar RNC com os usuários selecionados
                for user_id in users_to_share:
                    if user_id != session['user_id']:
                        cursor.execute('''
                            INSERT INTO rnc_shares 
                            (rnc_id, shared_by_user_id, shared_with_user_id, permission_level)
                            VALUES (?, ?, ?, 'assigned')
                        ''', (rnc_id, session['user_id'], user_id))
                
                logger.info(f"✓ RNC {rnc_id} atribuída para CAUSADOR (ID: {causador_user_id}) + {gerentes_encontrados} gerente(s) do grupo {assigned_group_id}")
                logger.info(f"  Total de pessoas que receberão: {len(users_to_share)}")
                for uid in users_to_share:
                    logger.info(f"    - User ID: {uid}")
                
                # ============================================
                # COMPARTILHAMENTO AUTOMÁTICO COM RONALDO (VALORISTA)
                # SOMENTE quando há causador específico
                # ============================================
                RONALDO_ID = 11
                try:
                    # Verificar se Ronaldo não é o criador da RNC e não está na lista
                    if session['user_id'] != RONALDO_ID and RONALDO_ID not in users_to_share:
                        cursor.execute('''
                            INSERT INTO rnc_shares 
                            (rnc_id, shared_by_user_id, shared_with_user_id, permission_level)
                            VALUES (?, ?, ?, 'valorista')
                        ''', (rnc_id, session['user_id'], RONALDO_ID))
                        logger.info(f"  ✓ Ronaldo (Valorista) adicionado automaticamente")
                        logger.info(f"  Total FINAL de pessoas: {len(users_to_share) + 1}")
                except Exception as e:
                    logger.error(f"  ✗ Erro ao compartilhar RNC com Ronaldo: {e}")
                
                logger.info(f"={'*'*80}")
                logger.info(f"RESUMO FINAL - MODO 2 (Causador Específico):")
                logger.info(f"  RNC ID: {rnc_id}")
                logger.info(f"  Causador: ID {causador_user_id}")
                logger.info(f"  Grupo: ID {assigned_group_id}")
                logger.info(f"  Total que receberão: {len(users_to_share) + (1 if RONALDO_ID not in users_to_share else 0)}")
                logger.info(f"={'*'*80}")
                
            except Exception as e:
                logger.error(f" Erro ao atribuir RNC ao causador + gerentes: {e}")
                import traceback
                logger.error(traceback.format_exc())
        
        elif assigned_user_ids and len(assigned_user_ids) > 0:
            # MODO 3: Atribuir para USUÁRIOS ESPECÍFICOS (lista personalizada)
            try:
                for user_id in assigned_user_ids:
                    if user_id and int(user_id) != session['user_id']:
                        cursor.execute('''
                            INSERT INTO rnc_shares 
                            (rnc_id, shared_by_user_id, shared_with_user_id, permission_level)
                            VALUES (?, ?, ?, 'assigned')
                        ''', (rnc_id, session['user_id'], int(user_id)))
                logger.info(f" RNC {rnc_id} atribuída a {len(assigned_user_ids)} usuário(s) específico(s)")
            except Exception as e:
                logger.error(f" Erro ao salvar atribuições de usuários: {e}")

        # ============================================
        # BUSCAR USUÁRIOS COMPARTILHADOS ANTES DE FECHAR CONEXÃO
        # ============================================
        shared_users_list = []
        try:
            cursor.execute('''
                SELECT DISTINCT shared_with_user_id 
                FROM rnc_shares 
                WHERE rnc_id = ? AND shared_with_user_id != ?
            ''', (rnc_id, session['user_id']))
            shared_users_list = [row[0] for row in cursor.fetchall()]
            logger.info(f" Encontrados {len(shared_users_list)} usuários compartilhados para notificar")
        except Exception as e:
            logger.error(f" Erro ao buscar usuários compartilhados: {e}")

        try:
            conn.commit()
        finally:
            conn.close()

        try:
            clear_rnc_cache()
        except Exception:
            pass

        # ============================================
        # ENVIO DE NOTIFICAÇÕES POR EMAIL
        # ============================================
        try:
            from services.email_notifications import notify_new_rnc
            notification_result = notify_new_rnc(rnc_id)
            
            if notification_result['success']:
                logger.info(f" Notificações enviadas para RNC {rnc_id}: {notification_result['sent']} enviadas, {notification_result['failed']} falharam")
            else:
                logger.warning(f" Falha ao enviar notificações para RNC {rnc_id}: {notification_result['message']}")
                
        except Exception as e:
            # Não falhar a criação da RNC se houver erro nas notificações
            logger.error(f" Erro ao enviar notificações para RNC {rnc_id}: {e}")

        # ============================================
        # ENVIO DE NOTIFICAÇÕES EM TEMPO REAL (SocketIO)
        # ============================================
        try:
            from flask import current_app
            socketio = current_app.extensions.get('socketio')
            
            if socketio and len(shared_users_list) > 0:
                # Buscar informações do criador
                conn_notify = sqlite3.connect(DB_PATH)
                cursor_notify = conn_notify.cursor()
                
                cursor_notify.execute('SELECT name FROM users WHERE id = ?', (session['user_id'],))
                creator_info = cursor_notify.fetchone()
                creator_name = creator_info[0] if creator_info else 'Usuário'
                conn_notify.close()
                
                # Enviar notificação para cada usuário
                for user_id in shared_users_list:
                    # Notificação de compartilhamento (modal grande)
                    notification_data_share = {
                        'type': 'rnc_shared',
                        'title': ' Nova RNC Compartilhada',
                        'message': f'{creator_name} compartilhou a RNC {rnc_number} com você',
                        'rnc_id': rnc_id,
                        'rnc_number': rnc_number,
                        'rnc_title': data.get('title', 'RNC'),
                        'creator_name': creator_name,
                        'timestamp': datetime.now().isoformat(),
                        'priority': 'high'
                    }
                    
                    # Notificação de criação (pop-up lateral)
                    notification_data_created = {
                        'type': 'rnc_created',
                        'title': ' Nova RNC Criada',
                        'message': f'{creator_name} criou a RNC {rnc_number}: {data.get("title", "")[:50]}',
                        'rnc_id': rnc_id,
                        'rnc_number': rnc_number,
                        'rnc_title': data.get('title', 'RNC'),
                        'user_name': creator_name,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Emitir ambos os eventos SocketIO
                    logger.info(f" ========================================")
                    logger.info(f" ENVIANDO NOTIFICAÇÕES PARA USUÁRIO {user_id}")
                    logger.info(f" Room: user_{user_id}")
                    logger.info(f" Dados rnc_notification: {notification_data_share}")
                    logger.info(f" Dados rnc_created: {notification_data_created}")
                    
                    socketio.emit('rnc_notification', notification_data_share, room=f'user_{user_id}')
                    socketio.emit('rnc_created', notification_data_created, room=f'user_{user_id}')
                    
                    logger.info(f" Notificações emitidas com sucesso!")
                    logger.info(f" ========================================")
            else:
                logger.info(f" Nenhum usuário para notificar ou SocketIO não disponível")
                    
        except Exception as e:
            logger.error(f" Erro ao enviar notificação em tempo real: {e}")

        return jsonify({
            'success': True,
            'message': 'RNC criado com sucesso!',
            'rnc_id': rnc_id,
            'rnc_number': rnc_number
        })
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        logger.error(f"Erro ao criar RNC: {e}")
        return jsonify({'success': False, 'message': 'Erro interno ao criar RNC'}), 500


@rnc.route('/api/rnc/<int:rnc_id>/valores-itens', methods=['GET'])
def get_rnc_valores_itens(rnc_id):
    """Retorna os itens de valores/hora de uma RNC"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Não autenticado'}), 401
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verificar se usuário tem acesso à RNC
        cursor.execute('SELECT id FROM rncs WHERE id = ?', (rnc_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'RNC não encontrada'}), 404
        
        # Buscar itens de valores
        cursor.execute('''
            SELECT id, codigo, descricao, setor, valor_hora, horas, subtotal, created_at
            FROM rnc_valores_itens
            WHERE rnc_id = ?
            ORDER BY id ASC
        ''', (rnc_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        itens = []
        total = 0
        for row in rows:
            item = {
                'id': row[0],
                'codigo': row[1],
                'descricao': row[2],
                'setor': row[3],
                'valor_hora': float(row[4]),
                'horas': float(row[5]),
                'subtotal': float(row[6]),
                'created_at': row[7]
            }
            itens.append(item)
            total += item['subtotal']
        
        return jsonify({
            'success': True,
            'itens': itens,
            'total': total,
            'count': len(itens)
        })
        
    except Exception as e:
        logger.error(f"Erro ao buscar itens de valores da RNC {rnc_id}: {e}")
        return jsonify({'success': False, 'message': 'Erro ao buscar itens'}), 500


@rnc.route('/rnc/<int:rnc_id>/chat')
def rnc_chat(rnc_id):
    if 'user_id' not in session:
        return redirect('/')
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
         SELECT r.*, u.name as user_name, au.name as assigned_user_name,
             u.department as user_department, au.department as assigned_user_department
            FROM rncs r
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN users au ON r.assigned_user_id = au.id
            WHERE r.id = ?
        ''', (rnc_id,))
        rnc_row = cursor.fetchone()
        # Capturar os nomes das colunas antes de executar outras queries
        rnc_columns = [d[0] for d in cursor.description] if cursor.description else []
        if not rnc_row:
            conn.close()
            return render_template('error.html', message='RNC não encontrado'), 404
        cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        current_user = cursor.fetchone()
        cursor.execute('''
            SELECT cm.id, cm.user_id, u.name, cm.message, cm.message_type, cm.created_at
            FROM chat_messages cm
            JOIN users u ON cm.user_id = u.id
            WHERE cm.rnc_id = ?
            ORDER BY cm.created_at ASC
        ''', (rnc_id,))
        messages = cursor.fetchall()
        conn.close()
        # Mapear RNC para dict para acesso via rnc.id / rnc.rnc_number no template
        rnc_dict = {}
        try:
            if rnc_row and rnc_columns:
                rnc_dict = dict(zip(rnc_columns, rnc_row))
            else:
                # Fallback mÃ­nimo
                rnc_dict = {'id': rnc_id}
        except Exception:
            rnc_dict = {'id': rnc_id}
        return render_template('rnc_chat.html', rnc=rnc_dict, current_user=current_user, messages=messages)
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return render_template('error.html', message='Erro interno do sistema'), 500


@rnc.route('/api/rnc/list')
def list_rncs():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401

    conn = None
    try:
        from services.permissions import has_permission
        from services.db import get_db_connection, return_db_connection
        from services.cache import get_cached_query, cache_query
        try:
            # Local import to avoid cyclic/analysis issues
            from services.pagination import parse_cursor_limit, compute_window  # type: ignore
        except Exception:
            import importlib
            pagination = importlib.import_module('services.pagination')
            parse_cursor_limit = getattr(pagination, 'parse_cursor_limit')
            compute_window = getattr(pagination, 'compute_window')
        tab = request.args.get('tab', 'active')
        user_id = session['user_id']
        force_refresh = request.args.get('_t') is not None

        # ======= FILTROS DE PESQUISA =======
        filter_cv = request.args.get('cv', '').strip()
        filter_rnc_number = request.args.get('rnc_number', '').strip()
        filter_client = request.args.get('client', '').strip()
        filter_equipment = request.args.get('equipment', '').strip()
        filter_responsavel = request.args.get('responsavel', '').strip()
        filter_setor = request.args.get('setor', '').strip()
        filter_area_responsavel = request.args.get('area_responsavel', '').strip()
        filter_mp = request.args.get('mp', '').strip()
        filter_conjunto = request.args.get('conjunto', '').strip()
        filter_modelo = request.args.get('modelo', '').strip()
        
        # ======= FILTROS ADICIONAIS =======
        # Aceitar parâmetro de ano (year) e status (status) para filtragem simplificada
        filter_year = request.args.get('year', '').strip()
        filter_status = request.args.get('status', '').strip()

        # ======= FILTROS DE DATA =======
        # Aceitar vários formatos/nomeclaturas de parâmetro vindos do frontend
        filter_date_from = (request.args.get('date_from') or request.args.get('dateStart') or request.args.get('date_start') or '').strip()  # Data inicial (De:)
        filter_date_to = (request.args.get('date_to') or request.args.get('dateEnd') or request.args.get('date_end') or '').strip()      # Data final (Até:)

        # Se foi fornecido apenas o ano, derive o intervalo completo do ano
        if filter_year and not (filter_date_from or filter_date_to):
            try:
                y = int(str(filter_year).strip()[:4])
                filter_date_from = f"{y}-01-01"
                filter_date_to = f"{y}-12-31"
            except Exception:
                # ignorar se o year não for válido
                pass

        # Criar chave de cache incluindo filtros
        filters_hash = f"{filter_cv}_{filter_rnc_number}_{filter_client}_{filter_equipment}_{filter_responsavel}_{filter_setor}_{filter_area_responsavel}_{filter_mp}_{filter_conjunto}_{filter_modelo}_{filter_date_from}_{filter_date_to}_{filter_year}_{filter_status}"

        # Cursor-based pagination params (shared util)
        cursor_id, limit = parse_cursor_limit(request, default_limit=50000, max_limit=50000)

        cache_key = f"rncs_list_{user_id}_{tab}_{cursor_id}_{limit}_{filters_hash}"
        if not force_refresh:
            cached_result = get_cached_query(cache_key)
            if cached_result:
                logger.info(f"Retornando cache para {cache_key}")
                return jsonify(cached_result)
        else:
            logger.info(f"Force refresh solicitado - ignorando cache para {cache_key}")

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Obter departamento do usuário para filtro adicional
        cursor.execute('SELECT department FROM users WHERE id = ?', (user_id,))
        user_dept_row = cursor.fetchone()
        user_department = user_dept_row[0] if user_dept_row else None
        
        # Build query with cursor-based pagination
        view_all_active = has_permission(user_id, 'view_all_rncs')
        view_all_finalized = has_permission(user_id, 'view_finalized_rncs')

        select_prefix = "SELECT"
        joins = [
            "FROM rncs r",
            "LEFT JOIN users u ON r.user_id = u.id",
            "LEFT JOIN users au ON r.assigned_user_id = au.id",
            "LEFT JOIN users causador_u ON r.causador_user_id = causador_u.id",
        ]
        where = ["(r.is_deleted = 0 OR r.is_deleted IS NULL)"]
        params = []

        if tab == 'finalized':
            # Permitir que o frontend sobreponha o status padrão
            if filter_status:
                where.append("r.status = ?")
                params.append(filter_status)
            else:
                where.append("r.status = 'Finalizado'")
            if not view_all_finalized:
                joins.append("LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id")
                joins.append("LEFT JOIN users user_group ON user_group.id = ?")
                
                # ============================================
                # LÓGICA DE VISIBILIDADE - RNCs FINALIZADAS
                # Mostrar todas as RNCs finalizadas relacionadas ao usuário
                # SEM filtro de gerente (finalizadas devem aparecer para todos)
                # ============================================
                permission_conditions = [
                    "r.user_id = ?",
                    "r.assigned_user_id = ?",
                    "rs.shared_with_user_id = ?"
                ]
                
                # Se o usuário tem departamento, incluir RNCs da mesma área (LIKE para pegar variações)
                if user_department:
                    permission_conditions.append("LOWER(TRIM(r.area_responsavel)) LIKE LOWER(TRIM(?))")
                    permission_conditions.append("LOWER(TRIM(r.setor)) LIKE LOWER(TRIM(?))")
                    params.extend([user_id, user_id, user_id, user_id, f'%{user_department.strip()}%', f'%{user_department.strip()}%'])
                else:
                    params.extend([user_id, user_id, user_id, user_id])
                
                # REMOVIDO: Lógica que adicionava assigned_group_id
                # Isso causava o bug de mostrar TODAS as RNCs do grupo
                # Agora só mostra RNCs explicitamente compartilhadas via rnc_shares
                where.append(f"({' OR '.join(permission_conditions)})")
                select_prefix = "SELECT DISTINCT"
        elif tab.lower() in ('engineering', 'engenharia'):
            # Aba especÃ­fica de ENGENHARIA: mostrar somente RNCs FINALIZADOS da Ã¡rea/setor Engenharia
            # Isso antes era tratado como 'active' por não haver ramificação dedicada.
                # Filtra explicitamente por Engenharia (area_responsavel ou setor contém 'engenharia')
                # Ou por RNC atribuída a um grupo cujo nome contenha 'engenharia'.
                # Nota: não exigimos status='Finalizado' aqui para que RNCs encaminhadas
                # para Engenharia apareçam mesmo antes da finalização.
                where.append("(LOWER(TRIM(r.area_responsavel)) LIKE '%engenharia%' OR LOWER(TRIM(r.setor)) LIKE '%engenharia%' OR (r.assigned_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM groups g WHERE g.id = r.assigned_group_id AND LOWER(g.name) LIKE '%engenharia%')))")
                if not view_all_finalized:
                    joins.append("LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id")
                    joins.append("LEFT JOIN users user_group_eng ON user_group_eng.id = ?")
                
                    # ============================================
                    # LÓGICA DE VISIBILIDADE CORRIGIDA (ENGENHARIA)
                    # Inclui condição para gerentes/sub-gerentes
                    # ============================================
                    permission_conditions = [
                        "r.user_id = ?",
                        "r.assigned_user_id = ?",
                        "rs.shared_with_user_id = ?",
                        # Se o usuário é gerente ou sub-gerente do grupo atribuído à RNC
                        "(r.assigned_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM groups g WHERE g.id = r.assigned_group_id AND (g.manager_user_id = ? OR g.sub_manager_user_id = ?)))"
                    ]
                    params.extend([user_id, user_id, user_id, user_id, user_id, user_id])
                    where.append(f"({' OR '.join(permission_conditions)})")
                    select_prefix = "SELECT DISTINCT"
        else:
            # default to active - mostrar apenas RNCs NÃO finalizadas
            # CORRIGIDO: Filtrar por status mesmo para admin, aba "active" não deve mostrar finalizadas
            where.append("r.status NOT IN ('Finalizado')")
            
            if not view_all_active:
                # Usuário normal vê apenas suas RNCs ativas
                joins.append("LEFT JOIN rnc_shares rs ON rs.rnc_id = r.id")
                joins.append("LEFT JOIN users user_group_active ON user_group_active.id = ?")
                
                # ============================================
                # LÓGICA DE VISIBILIDADE CORRIGIDA (ACTIVE)
                # Inclui condição para gerentes/sub-gerentes
                # ============================================
                permission_conditions_active = [
                    "r.user_id = ?",
                    "r.assigned_user_id = ?",
                    "rs.shared_with_user_id = ?",
                    # Se o usuário é gerente ou sub-gerente do grupo atribuído à RNC
                    "(r.assigned_group_id IS NOT NULL AND EXISTS (SELECT 1 FROM groups g WHERE g.id = r.assigned_group_id AND (g.manager_user_id = ? OR g.sub_manager_user_id = ?)))"
                ]
                
                # Se o usuário tem departamento, incluir RNCs da mesma área (LIKE para pegar variações)
                if user_department:
                    permission_conditions_active.append("LOWER(TRIM(r.area_responsavel)) LIKE LOWER(TRIM(?))")
                    permission_conditions_active.append("LOWER(TRIM(r.setor)) LIKE LOWER(TRIM(?))")
                    params.extend([user_id, user_id, user_id, user_id, user_id, user_id, f'%{user_department.strip()}%', f'%{user_department.strip()}%'])
                else:
                    params.extend([user_id, user_id, user_id, user_id, user_id, user_id])
                
                # REMOVIDO: Lógica de assigned_group_id (causava bug)
                where.append(f"({' OR '.join(permission_conditions_active)})")
                select_prefix = "SELECT DISTINCT"

        if cursor_id is not None:
            # Desc order, so use r.id < cursor for next page
            where.append("r.id < ?")
            params.append(cursor_id)

        # ======= APLICAR FILTROS DE PESQUISA =======
        if filter_cv:
            where.append("LOWER(TRIM(r.cv)) LIKE LOWER(TRIM(?))")
            params.append(f"%{filter_cv}%")
        
        if filter_rnc_number:
            where.append("LOWER(TRIM(r.rnc_number)) LIKE LOWER(TRIM(?))")
            params.append(f"%{filter_rnc_number}%")
        
        if filter_client:
            where.append("LOWER(TRIM(r.client)) LIKE LOWER(TRIM(?))")
            params.append(f"%{filter_client}%")
        
        if filter_equipment:
            where.append("LOWER(TRIM(r.equipment)) LIKE LOWER(TRIM(?))")
            params.append(f"%{filter_equipment}%")
        
        if filter_responsavel:
            where.append("LOWER(TRIM(r.responsavel)) LIKE LOWER(TRIM(?))")
            params.append(f"%{filter_responsavel}%")
        
        if filter_setor:
            where.append("LOWER(TRIM(r.setor)) LIKE LOWER(TRIM(?))")
            params.append(f"%{filter_setor}%")
        
        if filter_area_responsavel:
            where.append("LOWER(TRIM(r.area_responsavel)) LIKE LOWER(TRIM(?))")
            params.append(f"%{filter_area_responsavel}%")
        
        if filter_mp:
            where.append("LOWER(TRIM(r.mp)) LIKE LOWER(TRIM(?))")
            params.append(f"%{filter_mp}%")
        
        if filter_conjunto:
            where.append("LOWER(TRIM(r.conjunto)) LIKE LOWER(TRIM(?))")
            params.append(f"%{filter_conjunto}%")
        
        if filter_modelo:
            where.append("LOWER(TRIM(r.modelo)) LIKE LOWER(TRIM(?))")
            params.append(f"%{filter_modelo}%")
        
        # ======= FILTROS DE DATA =======
        # Filtrar por data de criação ou finalização dependendo da aba
        if filter_date_from:
            # Validar formato de data (YYYY-MM-DD ou DD/MM/YYYY)
            try:
                # Tentar converter para formato ISO se vier em formato brasileiro
                if '/' in filter_date_from:
                    parts = filter_date_from.split('/')
                    if len(parts) == 3:
                        filter_date_from = f"{parts[2]}-{parts[1]}-{parts[0]}"  # DD/MM/YYYY -> YYYY-MM-DD
                
                # Para aba finalized, filtrar por finalized_at, senão por created_at
                if tab == 'finalized':
                    where.append("(DATE(r.finalized_at) >= DATE(?) OR (r.finalized_at IS NULL AND DATE(r.created_at) >= DATE(?)))")
                    params.extend([filter_date_from, filter_date_from])
                else:
                    where.append("DATE(r.created_at) >= DATE(?)")
                    params.append(filter_date_from)
            except Exception as e:
                logger.warning(f"Formato de data inválido (date_from): {filter_date_from} - {e}")
        
        if filter_date_to:
            # Validar formato de data
            try:
                # Tentar converter para formato ISO se vier em formato brasileiro
                if '/' in filter_date_to:
                    parts = filter_date_to.split('/')
                    if len(parts) == 3:
                        filter_date_to = f"{parts[2]}-{parts[1]}-{parts[0]}"  # DD/MM/YYYY -> YYYY-MM-DD
                
                # Para aba finalized, filtrar por finalized_at, senão por created_at
                if tab == 'finalized':
                    where.append("(DATE(r.finalized_at) <= DATE(?) OR (r.finalized_at IS NULL AND DATE(r.created_at) <= DATE(?)))")
                    params.extend([filter_date_to, filter_date_to])
                else:
                    where.append("DATE(r.created_at) <= DATE(?)")
                    params.append(filter_date_to)
            except Exception as e:
                logger.warning(f"Formato de data inválido (date_to): {filter_date_to} - {e}")

        columns = (
            "r.id, r.rnc_number, r.title, r.description, r.equipment, r.client, r.priority, r.status, "
            "r.user_id, r.assigned_user_id, r.created_at, r.updated_at, r.finalized_at, "
            "r.responsavel, r.setor, r.area_responsavel, au.name AS assigned_user_name, u.name AS user_name, "
            "r.cv, r.mp, r.conjunto, r.modelo, r.drawing, r.description_drawing, "
            "causador_u.name AS causador_nome, r.ass_responsavel AS setor_responsavel"
        )

        sql = f"""
            {select_prefix}
                {columns}
            {' '.join(joins)}
            WHERE {' AND '.join(where)}
            ORDER BY r.id DESC
            LIMIT ?
        """
        params_with_limit = params + [limit + 1]  # fetch one extra row to detect has_more
        cursor.execute(sql, tuple(params_with_limit))

        rncs_rows = cursor.fetchall()
        rncs_rows, has_more, next_cursor = compute_window(rncs_rows, limit, id_index=0)
        logger.info(f"ðŸ” Query executada para {tab}: {len(rncs_rows)} RNCs retornados (limit={limit}, has_more={has_more})")

        current_user_id = session['user_id']
        formatted_rncs = [
            {
                'id': rnc[0],
                'rnc_number': rnc[1],
                # CORRIGIDO: Usar description_drawing (índice 23) como fallback ao invés de description
                'title': (rnc[2] if (rnc[2] and str(rnc[2]).strip()) else (rnc[23][:100] + '...' if (len(rnc) > 23 and rnc[23] and len(str(rnc[23])) > 100) else (rnc[23] if (len(rnc) > 23 and rnc[23]) else 'RNC sem título'))),
                'description': rnc[3] if len(rnc) > 3 else None,
                'equipment': rnc[4] if len(rnc) > 4 else None,
                'client': rnc[5] if len(rnc) > 5 else None,
                'priority': rnc[6] if len(rnc) > 6 else 'Média',
                'status': rnc[7] if len(rnc) > 7 else 'Pendente',
                'user_id': rnc[8] if len(rnc) > 8 else None,
                'assigned_user_id': rnc[9] if len(rnc) > 9 else None,
                'created_at': rnc[10] if len(rnc) > 10 else None,
                'updated_at': rnc[11] if len(rnc) > 11 else None,
                'finalized_at': rnc[12] if len(rnc) > 12 else None,
                'responsavel': rnc[13] if (len(rnc) > 13 and rnc[13]) else 'N/A',  # Responsável do TXT
                'setor': rnc[14] if (len(rnc) > 14 and rnc[14]) else 'N/A',  # Setor do TXT
                'area_responsavel': rnc[15] if (len(rnc) > 15 and rnc[15]) else 'N/A',  # Ãrea responsÃ¡vel do TXT
                'assigned_user_name': rnc[16] if len(rnc) > 16 else None,
                'user_name': (rnc[17] if (len(rnc) > 17 and rnc[17]) else 'N/A'),  # Nome real do criador
                'user_department': rnc[14] if (len(rnc) > 14 and rnc[14]) else 'N/A',  # Para compatibilidade
                'department': rnc[15] if (len(rnc) > 15 and rnc[15]) else 'N/A',  # Ãrea responsÃ¡vel
                'is_creator': (current_user_id == rnc[8]) if len(rnc) > 8 else False,
                'is_assigned': (current_user_id == rnc[9]) if len(rnc) > 9 else False,
                'cv': rnc[18] if len(rnc) > 18 else None,
                'mp': rnc[19] if len(rnc) > 19 else None,
                'conjunto': rnc[20] if len(rnc) > 20 else None,
                'modelo': rnc[21] if len(rnc) > 21 else None,
                'drawing': rnc[22] if len(rnc) > 22 else None,
                'description_drawing': rnc[23] if len(rnc) > 23 else None,
                # NOVOS CAMPOS: Nome do causador e setor responsável da visualização da RNC
                'causador_nome': rnc[24] if (len(rnc) > 24 and rnc[24]) else None,  # Nome do causador (da assinatura)
                'setor_responsavel': rnc[25] if (len(rnc) > 25 and rnc[25]) else None  # Setor responsável (da assinatura)
            }
            for rnc in rncs_rows
        ]

        result = {
            'success': True,
            'rncs': formatted_rncs,
            'tab': tab,
            'limit': limit,
            'next_cursor': next_cursor,
            'has_more': has_more,
        }
        # Cache the result (Redis-backed with in-memory fallback)
        cache_query(cache_key, result, ttl=120)

        response = jsonify(result)
        response.headers['Cache-Control'] = 'public, max-age=120' if not force_refresh else 'no-cache'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    except Exception as e:
        logger.error(f"Erro ao listar RNCs: {e}")
        return jsonify({'success': False, 'message': f'Erro interno: {str(e)}'}), 500
    finally:
        if conn:
            try:
                from services.db import return_db_connection
                return_db_connection(conn)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

@rnc.route('/api/rnc/get/<int:rnc_id>', methods=['GET'])
def api_get_rnc(rnc_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('PRAGMA table_info(rncs)')
        columns = [row[1] for row in cursor.fetchall()]
        cursor.execute('SELECT * FROM rncs WHERE id = ?', (rnc_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return jsonify({'success': False, 'message': 'RNC não encontrada'}), 404
        rnc_dict = dict(zip(columns, row))
        for key in rnc_dict:
            if key.startswith('disposition_') or key.startswith('inspection_'):
                rnc_dict[key] = bool(rnc_dict[key])
        return jsonify({'success': True, 'rnc': rnc_dict})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro interno: {str(e)}'}), 500


@rnc.route('/rnc/<int:rnc_id>')
def view_rnc(rnc_id):
    if 'user_id' not in session:
        return redirect('/')
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.*,
                   u.name as user_name,
                   au.name as assigned_user_name,
                   u.department as user_department,
                   au.department as assigned_user_department,
                   g.name as area_responsavel_name,
                   CASE 
                       WHEN r.responsavel GLOB '[0-9]*' 
                       THEN (SELECT name FROM users WHERE id = CAST(r.responsavel AS INTEGER))
                       ELSE r.responsavel 
                   END as responsavel_name,
                   CASE 
                       WHEN r.inspetor GLOB '[0-9]*' 
                       THEN (SELECT name FROM users WHERE id = CAST(r.inspetor AS INTEGER))
                       ELSE r.inspetor 
                   END as inspetor_name,
                   cu.name as causador_name
            FROM rncs r
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN users au ON r.assigned_user_id = au.id
            LEFT JOIN groups g ON g.id = CAST(r.area_responsavel AS INTEGER)
            LEFT JOIN users cu ON r.causador_user_id = cu.id
            WHERE r.id = ?
        ''', (rnc_id,))
        rnc_data = cursor.fetchone()
        conn.close()
        
        if not rnc_data:
            return render_template('error.html', message='RNC não encontrado')
        
        if not isinstance(rnc_data, (tuple, list)):
            return render_template('error.html', message='Erro interno do sistema')

        try:
            conn_cols = sqlite3.connect(DB_PATH)
            cur_cols = conn_cols.cursor()
            cur_cols.execute('PRAGMA table_info(rncs)')
            base_columns = [row[1] for row in cur_cols.fetchall()]
            conn_cols.close()
        except Exception:
            base_columns = [
                'id','rnc_number','title','description','equipment','client','priority','status','user_id','assigned_user_id',
                'is_deleted','deleted_at','finalized_at','created_at','updated_at','disposition_usar','disposition_retrabalhar',
                'disposition_rejeitar','disposition_sucata','disposition_devolver_estoque','disposition_devolver_fornecedor',
                'inspection_reprovado','inspection_ver_rnc','signature_inspection_date','signature_engineering_date',
                'signature_inspection2_date','signature_inspection_name','signature_engineering_name','inspection_aprovado',
                'signature_inspection2_name','price','department','instruction_retrabalho','cause_rnc','action_rnc',
                'responsavel','inspetor','setor','material','quantity','drawing','area_responsavel','ass_responsavel','mp','revision',
                'position','cv','conjunto','modelo','description_drawing','purchase_order','assigned_group_id','causador_user_id'
            ]

        columns = base_columns + ['user_name', 'assigned_user_name', 'user_department', 'assigned_user_department', 'area_responsavel_name', 'responsavel_name', 'inspetor_name', 'causador_name']

        if len(rnc_data) < len(columns):
            rnc_data = list(rnc_data) + [None] * (len(columns) - len(rnc_data))

        rnc_dict = dict(zip(columns, rnc_data))

        # Função para extrair campos de texto da descrição
        def parse_label_map(text: str):
            if not text:
                return {}
            result = {}
            lines = text.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        if key and value:
                            result[key] = value
            return result

        # Extrair campos de texto da descrição para visualização
        txt_fields = parse_label_map(rnc_dict.get('description') or '')
        
        # Determinar criador de forma robusta usando o dict
        is_creator = str(session['user_id']) == str(rnc_dict.get('user_id'))
        
        return render_template('view_rnc_full.html', rnc=rnc_dict, txt_fields=txt_fields, is_creator=is_creator)
    except Exception as e:
        return render_template('error.html', message=f'Erro interno do sistema: {str(e)}')
        return render_template('view_rnc_full.html', rnc=rnc_dict, is_creator=is_creator, txt_fields=txt_fields)
    except Exception as e:
        logger.error(f"Erro ao visualizar RNC {rnc_id}: {e}")
        return render_template('error.html', message='Erro interno do sistema')


@rnc.route('/rnc/<int:rnc_id>/reply', methods=['GET'])
def reply_rnc(rnc_id):
    if 'user_id' not in session:
        return redirect('/')
    try:
        from services.permissions import has_permission
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.*, u.name as user_name, au.name as assigned_user_name
              FROM rncs r
              LEFT JOIN users u ON r.user_id = u.id
              LEFT JOIN users au ON r.assigned_user_id = au.id
             WHERE r.id = ?
        ''', (rnc_id,))
        rnc_data = cursor.fetchone()
        conn.close()

        if not rnc_data:
            return render_template('error.html', message='RNC não encontrado')

        owner_id = rnc_data[8]
        assigned_user_id = rnc_data[9] if len(rnc_data) > 9 else None
        is_creator = str(session['user_id']) == str(owner_id)
        is_assigned = assigned_user_id is not None and str(session['user_id']) == str(assigned_user_id)
        is_admin = has_permission(session['user_id'], 'admin_access')
        can_reply = has_permission(session['user_id'], 'reply_rncs')
        # Novo: permitir responder se o RNC foi compartilhado com o usuÃ¡rio (qualquer nÃ­vel)
        shared_can_reply = False
        try:
            conn_share = sqlite3.connect(DB_PATH)
            cur_share = conn_share.cursor()
            cur_share.execute('SELECT 1 FROM rnc_shares WHERE rnc_id = ? AND shared_with_user_id = ? LIMIT 1', (rnc_id, session['user_id']))
            shared_can_reply = cur_share.fetchone() is not None
            conn_share.close()
        except Exception:
            shared_can_reply = False

        if not (is_creator or is_assigned or is_admin or can_reply or shared_can_reply):
            return render_template('error.html', message='Acesso negado: você não tem permissão para responder este RNC')

        try:
            conn_cols = sqlite3.connect(DB_PATH)
            cur_cols = conn_cols.cursor()
            cur_cols.execute('PRAGMA table_info(rncs)')
            base_columns = [row[1] for row in cur_cols.fetchall()]
            conn_cols.close()
        except Exception:
            base_columns = [
                'id','rnc_number','title','description','equipment','client','priority','status','user_id','assigned_user_id',
                'is_deleted','deleted_at','finalized_at','created_at','updated_at','disposition_usar','disposition_retrabalhar',
                'disposition_rejeitar','disposition_sucata','disposition_devolver_estoque','disposition_devolver_fornecedor',
                'inspection_aprovado','inspection_reprovado','inspection_ver_rnc','signature_inspection_date','signature_engineering_date',
                'signature_inspection2_date','signature_inspection_name','signature_engineering_name','signature_inspection2_name','price'
            ]
        columns = base_columns + ['user_name', 'assigned_user_name']

        if len(rnc_data) < len(columns):
            rnc_data = list(rnc_data) + [None] * (len(columns) - len(rnc_data))

        rnc_dict = dict(zip(columns, rnc_data))
        
        # Adicionar função para extrair campos de texto da descrição
        def parse_label_map(text: str):
            if not text:
                return {}
            result = {}
            lines = text.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        if key and value:
                            result[key] = value
            return result
        
        # Extrair campos de texto da descrição
        txt_fields = parse_label_map(rnc_dict.get('description') or '')
        
        # Buscar lista de clientes do banco de dados
        clients = []
        try:
            conn_clients = sqlite3.connect(DB_PATH)
            cursor_clients = conn_clients.cursor()
            cursor_clients.execute('SELECT DISTINCT name FROM clients ORDER BY name')
            clients = [row[0] for row in cursor_clients.fetchall() if row[0]]
            conn_clients.close()
            logger.info(f"✅ Carregados {len(clients)} clientes para reply_rnc")
        except Exception as e:
            logger.warning(f"Erro ao carregar clientes para reply_rnc: {e}")
            clients = []
        
        return render_template('edit_rnc_form.html', rnc=rnc_dict, txt_fields=txt_fields, is_editing=True, is_reply=True, clients=clients)
    except Exception as e:
        logger.error(f"Erro ao abrir modo Responder para RNC {rnc_id}: {e}")
        return render_template('error.html', message='Erro interno do sistema')


@rnc.route('/rnc/<int:rnc_id>/print')
def print_rnc(rnc_id):
    if 'user_id' not in session:
        return redirect('/')
    try:
        # Carregar dados básicos do RNC diretamente
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM rncs WHERE id = ?', (rnc_id,))
        rnc_data = cursor.fetchone()
        conn.close()
        if rnc_data is None:
            logger.error(f"Erro ao buscar RNC {rnc_id}")
            return render_template('error.html', message='RNC não encontrado')

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.*, 
                   u.name as user_name, 
                   au.name as assigned_user_name,
                   g.name as area_responsavel_name,
                   resp_user.name as responsavel_name,
                   insp_user.name as inspetor_name
            FROM rncs r 
            LEFT JOIN users u ON r.user_id = u.id 
            LEFT JOIN users au ON r.assigned_user_id = au.id
            LEFT JOIN groups g ON g.id = CAST(r.area_responsavel AS INTEGER)
            LEFT JOIN users resp_user ON resp_user.id = CAST(r.responsavel AS INTEGER)
            LEFT JOIN users insp_user ON insp_user.id = CAST(r.inspetor AS INTEGER)
            WHERE r.id = ?
        ''', (rnc_id,))
        row = cursor.fetchone()
        columns = [d[0] for d in cursor.description]
        conn.close()

        rnc_dict = dict(zip(columns, row)) if row else {}
        for date_key in ['created_at', 'updated_at', 'finalized_at']:
            if isinstance(rnc_dict.get(date_key), (tuple, list)):
                rnc_dict[date_key] = rnc_dict.get(date_key)[0]

        if 'price' not in rnc_dict:
            rnc_dict['price'] = 0
        if 'user_name' not in rnc_dict:
            rnc_dict['user_name'] = 'Sistema'

        def parse_label_map(text: str):
            """Extrai pares labelâ†’valor da descriÃ§Ã£o, tolerando diferentes separadores e abreviaÃ§Ãµes.
            Suporta linhas como:
              - "DES.: 123   REV - X   POS = 1   MOD  ABC"
              - "QTDE LOTE: 25" â†’ Quantidade
              - "DESCRIÃ‡ÃƒO DES.: ..." â†’ DescriÃ§Ã£o da RNC/DescriÃ§Ã£o do desenho
            """
            import re, unicodedata
            if not text:
                return {}
            def _norm(s: str) -> str:
                s = unicodedata.normalize('NFD', s)
                s = ''.join(ch for ch in s if unicodedata.category(ch) != 'Mn')
                s = s.lower()
                s = re.sub(r'[^a-z0-9]', '', s)
                return s
            # Suporta: ":", "-", "â€”", "=", ou 2+ espaÃ§os como separador
            sep_re = re.compile(r'^\s*([A-Za-zÃ€-Ã¿\.\s/_-]{2,}?)\s*(?:[:=\-\u2013\u2014]+|\s{2,})\s*(.+)$')
            token_re = re.compile(r'^\s*([A-Za-zÃ€-Ã¿\.]{2,})\s+(.+)$')
            mapping: dict[str, str] = {}
            lines = [ln.rstrip() for ln in str(text).split('\n') if ln.strip()]
            for ln in lines:
                m = sep_re.match(ln)
                if not m:
                    m = token_re.match(ln)
                if not m:
                    continue
                label, val = m.group(1).strip(), m.group(2).strip()
                n = _norm(label)
                if n in {'des', 'desenho'}:
                    mapping['Desenho'] = val
                elif n in {'mp'}:
                    mapping['MP'] = val
                elif n in {'rev', 'revisao'}:
                    mapping['RevisÃ£o'] = val
                elif n == 'cv' or 'cv' in n:
                    mapping['CV'] = val
                elif n == 'pos' or 'pos' in n:
                    mapping['POS'] = val
                elif 'conjunto' in n or n == 'conj':
                    mapping['Conjunto'] = val
                elif n in {'modelo', 'mod'}:
                    mapping['Modelo'] = val
                elif n == 'quantidade' or n.startswith('qtde') or n.startswith('qtd'):
                    mapping['Quantidade'] = val
                elif 'material' in n or n == 'mat':
                    mapping['Material'] = val
                elif n in {'oc', 'ordemdecompra', 'ordemcompra'}:
                    mapping['OC'] = val
                elif ('area' in n and 'responsavel' in n) or n in {'arearesponsavel'}:
                    mapping['Ãrea responsÃ¡vel'] = val
                elif ('descricao' in n and 'rnc' in n) or n in {'descricaodes', 'descricaododesenho', 'descricaodesenho'}:
                    # Preencher ambos para mÃ¡xima compatibilidade com templates
                    mapping['DescriÃ§Ã£o da RNC'] = val
                    mapping['DescriÃ§Ã£o do desenho'] = val
                elif 'instrucao' in n and 'retrabalho' in n:
                    mapping['InstruÃ§Ã£o para retrabalho'] = val
                elif n in {'valor', 'vlr'}:
                    mapping['Valor'] = val
                else:
                    mapping[label] = val
            return mapping
        txt_fields = parse_label_map(rnc_dict.get('description') or '')
        # Usa o MESMO template da visualização, mas com flag de impressão
        return render_template('view_rnc_full.html', rnc=rnc_dict, txt_fields=txt_fields, print_mode=True)
    except Exception as e:
        logger.error(f"Erro ao gerar pÃ¡gina de impressÃ£o para RNC {rnc_id}: {e}")
        return render_template('error.html', message='Erro interno do sistema')


@rnc.route('/rnc/<int:rnc_id>/print-modelo')
def print_rnc_modelo(rnc_id):
    """Renderiza o novo modelo de impressÃ£o (templates/modelo.html) com todos os dados da RNC."""
    if 'user_id' not in session:
        return redirect('/')
    try:
        # Carregar linha completa com joins para nomes
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.*, u.name as user_name, au.name as assigned_user_name
            FROM rncs r 
            LEFT JOIN users u ON r.user_id = u.id 
            LEFT JOIN users au ON r.assigned_user_id = au.id
            WHERE r.id = ?
        ''', (rnc_id,))
        row = cursor.fetchone()
        columns = [d[0] for d in cursor.description] if cursor.description else []
        conn.close()
        if not row:
            return render_template('error.html', message='RNC não encontrado')

        rnc_dict = dict(zip(columns, row))
        # Normalizar booleans
        for key in list(rnc_dict.keys()):
            if key.startswith('disposition_') or key.startswith('inspection_'):
                try:
                    rnc_dict[key] = bool(rnc_dict[key])
                except Exception:
                    pass

        # Extrair campos rotulados do description
        def parse_label_map(text: str):
            """Extrai pares labelâ†’valor da descriÃ§Ã£o, tolerando diferentes separadores e abreviaÃ§Ãµes.
            Suporta linhas como:
              - "DES.: 123   REV - X   POS = 1   MOD  ABC"
              - "QTDE LOTE: 25" â†’ Quantidade
              - "DESCRIÃ‡ÃƒO DES.: ..." â†’ DescriÃ§Ã£o da RNC/DescriÃ§Ã£o do desenho
            """
            import re, unicodedata
            if not text:
                return {}
            def _norm(s: str) -> str:
                s = unicodedata.normalize('NFD', s)
                s = ''.join(ch for ch in s if unicodedata.category(ch) != 'Mn')
                s = s.lower()
                s = re.sub(r'[^a-z0-9]', '', s)
                return s
            sep_re = re.compile(r'^\s*([A-Za-zÃ€-Ã¿\.\s/_-]{2,}?)\s*(?:[:=\-\u2013\u2014]+|\s{2,})\s*(.+)$')
            token_re = re.compile(r'^\s*([A-Za-zÃ€-Ã¿\.]{2,})\s+(.+)$')
            mapping: dict[str, str] = {}
            lines = [ln.rstrip() for ln in str(text).split('\n') if ln.strip()]
            for ln in lines:
                m = sep_re.match(ln)
                if not m:
                    m = token_re.match(ln)
                if not m:
                    continue
                label, val = m.group(1).strip(), m.group(2).strip()
                n = _norm(label)
                if n in {'des', 'desenho'}:
                    mapping['Desenho'] = val
                elif n in {'mp'}:
                    mapping['MP'] = val
                elif n in {'rev', 'revisao'}:
                    mapping['RevisÃ£o'] = val
                elif n == 'cv' or 'cv' in n:
                    mapping['CV'] = val
                elif n == 'pos' or 'pos' in n:
                    mapping['POS'] = val
                elif 'conjunto' in n or n == 'conj':
                    mapping['Conjunto'] = val
                elif n in {'modelo', 'mod'}:
                    mapping['Modelo'] = val
                elif n == 'quantidade' or n.startswith('qtde') or n.startswith('qtd'):
                    mapping['Quantidade'] = val
                elif 'material' in n or n == 'mat':
                    mapping['Material'] = val
                elif n in {'oc', 'ordemdecompra', 'ordemcompra'}:
                    mapping['OC'] = val
                elif ('area' in n and 'responsavel' in n) or n in {'arearesponsavel'}:
                    mapping['Ãrea responsÃ¡vel'] = val
                elif ('descricao' in n and 'rnc' in n) or n in {'descricaodes', 'descricaododesenho', 'descricaodesenho'}:
                    mapping['DescriÃ§Ã£o da RNC'] = val
                    mapping['DescriÃ§Ã£o do desenho'] = val
                elif 'instrucao' in n and 'retrabalho' in n:
                    mapping['InstruÃ§Ã£o para retrabalho'] = val
                elif n in {'valor', 'vlr'}:
                    mapping['Valor'] = val
                elif n in {'causa'}:
                    mapping['Causa'] = val
                elif 'acao' in n or 'acaosertomada' in n:
                    mapping['AÃ§Ã£o'] = val
                else:
                    mapping[label] = val
            return mapping

        txt_fields = parse_label_map(rnc_dict.get('description') or '')
        # Compatibilidade de nomes de depto
        if 'department' not in rnc_dict or not rnc_dict.get('department'):
            rnc_dict['department'] = rnc_dict.get('user_department')

        return render_template('modelo.html', rnc=rnc_dict, txt_fields=txt_fields)
    except Exception as e:
        logger.error(f"Erro ao renderizar modelo de impressÃ£o da RNC {rnc_id}: {e}")
        return render_template('error.html', message='Erro interno do sistema')


@rnc.route('/rnc/<int:rnc_id>/pdf-generator')
def pdf_generator(rnc_id):
    if 'user_id' not in session:
        return redirect('/')
    try:
        from services.permissions import has_permission
        # Carregar dados bÃ¡sicos do RNC
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM rncs WHERE id = ?', (rnc_id,))
        rnc_data = cursor.fetchone()
        conn.close()
        if rnc_data is None:
            logger.error(f"Erro ao buscar RNC {rnc_id}")
            return render_template('error.html', message='RNC não encontrado')

        user_id_index = 8
        try:
            if len(rnc_data) <= user_id_index:
                logger.error(f"RNC {rnc_id} nÃ£o tem dados suficientes: {len(rnc_data)} colunas")
                return render_template('error.html', message='Dados do RNC incompletos')
            user_id_from_rnc = rnc_data[user_id_index]
            user_has_permission = has_permission(session['user_id'], 'view_all_rncs')
            is_creator = (user_id_from_rnc == session['user_id'])
            if not user_has_permission and not is_creator:
                logger.warning(f"UsuÃ¡rio {session['user_id']} tentou acessar RNC {rnc_id} sem permissÃ£o")
                return render_template('error.html', message='Acesso negado')
        except Exception as access_error:
            logger.error(f"Erro ao verificar permissÃµes para RNC {rnc_id}: {access_error}")
            return render_template('error.html', message='Erro ao verificar permissÃµes')

        columns = [
            'id', 'rnc_number', 'title', 'description', 'equipment', 'client', 
            'priority', 'status', 'user_id', 'created_at', 'updated_at', 
            'assigned_user_id', 'disposition_usar', 'disposition_retrabalhar', 
            'disposition_rejeitar', 'disposition_sucata', 'disposition_devolver_estoque', 
            'disposition_devolver_fornecedor', 'inspection_aprovado', 'inspection_reprovado', 
            'inspection_ver_rnc', 'signature_inspection_date', 'signature_engineering_date', 
            'signature_inspection2_date', 'signature_inspection_name', 'signature_engineering_name', 
            'signature_inspection2_name', 'is_deleted', 'deleted_at', 'finalized_at',
            'user_name', 'assigned_user_name'
        ]
        if len(rnc_data) < len(columns):
            rnc_data = list(rnc_data) + [None] * (len(columns) - len(rnc_data))
        rnc_dict = dict(zip(columns, rnc_data))
        try:
            return render_template('view_rnc_pdf_js.html', rnc=rnc_dict)
        except Exception as template_error:
            logger.error(f"Erro ao renderizar template para RNC {rnc_id}: {template_error}")
            return render_template('error.html', message='Erro ao gerar pÃ¡gina')
    except Exception as e:
        logger.error(f"Erro ao acessar gerador de PDF para RNC {rnc_id}: {e}")
        return render_template('error.html', message='Erro interno do sistema')


@rnc.route('/rnc/<int:rnc_id>/download-pdf')
def download_rnc_pdf(rnc_id):
    """Download do PDF da RNC"""
    if 'user_id' not in session:
        return redirect('/')
    
    try:
        from services.pdf_generator import pdf_generator
        from services.permissions import has_permission
        
        # Verificar permissÃµes
        user_id = session['user_id']
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT user_id, assigned_user_id FROM rncs WHERE id = ? AND is_deleted = 0', (rnc_id,))
        rnc = cursor.fetchone()
        conn.close()
        
        if not rnc:
            return render_template('error.html', message='RNC não encontrada')
        
        rnc_creator_id = rnc[0]
        rnc_assigned_id = rnc[1]
        
        # Verificar permissÃµes
        is_creator = str(user_id) == str(rnc_creator_id)
        is_assigned = (rnc_assigned_id is not None and str(user_id) == str(rnc_assigned_id))
        is_admin = has_permission(user_id, 'admin_access')
        can_view = has_permission(user_id, 'view_all_rncs')
        
        # Verificar se foi compartilhada
        shared_can_view = False
        try:
            conn_share = sqlite3.connect(DB_PATH)
            cur_share = conn_share.cursor()
            cur_share.execute('SELECT 1 FROM rnc_shares WHERE rnc_id = ? AND shared_with_user_id = ? LIMIT 1', (rnc_id, user_id))
            shared_can_view = cur_share.fetchone() is not None
            conn_share.close()
        except Exception:
            shared_can_view = False
        
        if not (is_creator or is_assigned or is_admin or can_view or shared_can_view):
            return render_template('error.html', message='Acesso negado: você não tem permissão para visualizar esta RNC')
        
        # Gerar PDF
        pdf_path = pdf_generator.generate_pdf(rnc_id)
        if not pdf_path:
            return render_template('error.html', message='Erro ao gerar PDF da RNC')
        
        # Enviar arquivo para download
        from flask import send_file
        import os
        
        filename = os.path.basename(pdf_path)
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
        
    except Exception as e:
        logger.error(f"Erro ao gerar PDF da RNC {rnc_id}: {e}")
        return render_template('error.html', message='Erro interno ao gerar PDF')


# ROTA DE EDITAR REMOVIDA - SubstituÃ­da por /rnc/<id>/reply (Responder)
# Motivo: Simplificação do sistema - apenas responder é necessário
# Data: 2025-10-07

# @rnc.route('/rnc/<int:rnc_id>/edit', methods=['GET', 'POST'])
# def edit_rnc(rnc_id):
#     [CÃ“DIGO REMOVIDO - Use /rnc/<id>/reply para editar/responder RNCs]


@rnc.route('/api/rnc/<int:rnc_id>/update', methods=['PUT'])
@csrf_protect()
def update_rnc_api(rnc_id):
    logger.info(f"Iniciando atualização da RNC {rnc_id}")
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.permissions import has_permission
        from services.cache import clear_rnc_cache, query_cache, cache_lock
        from routes.field_locks import get_user_locked_fields
        
        # Validar campos bloqueados NO CONTEXTO DE RESPOSTA
        data = request.get_json() or {}
        locked_fields = get_user_locked_fields(session['user_id'], context='response')
        if locked_fields:
            attempted_fields = []
            for field in locked_fields:
                if field in data and data[field] is not None:
                    # Considerar valores vazios (incluindo datas vazias como "///", "//", "/", etc.)
                    field_value = str(data[field]).strip()
                    is_empty_date = field_value.replace('/', '').strip() == ''
                    
                    # Debug log
                    if field == 'signature_inspection_date':
                        logger.info(f" DEBUG signature_inspection_date: raw='{data[field]}', field_value='{field_value}', is_empty_date={is_empty_date}")
                    
                    if field_value != '' and not is_empty_date:
                        attempted_fields.append(field)
            
            if attempted_fields:
                logger.warning(f"Usuário {session['user_id']} tentou editar campos bloqueados na resposta: {attempted_fields}")
                return jsonify({
                    'success': False,
                    'message': f'Os seguintes campos estão bloqueados para seu grupo: {", ".join(attempted_fields)}'
                }), 403
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM rncs WHERE id = ?', (rnc_id,))
        rnc_data = cursor.fetchone()
        if not rnc_data:
            return jsonify({'success': False, 'message': 'RNC não encontrado'}), 404
        if not isinstance(rnc_data, (tuple, list)):
            logger.error(f"Erro: rnc_data não é uma tupla/lista: {type(rnc_data)} - {rnc_data}")
            return jsonify({'success': False, 'message': 'Erro interno do sistema'}), 500

        user_is_creator = str(rnc_data[8]) == str(session['user_id'])
        has_admin = has_permission(session['user_id'], 'admin_access')
        can_reply = has_permission(session['user_id'], 'reply_rncs')
        
        # Verificar se foi compartilhado com o usuário
        is_shared_with_user = False
        try:
            cur_shared = conn.cursor()
            cur_shared.execute('SELECT 1 FROM rnc_shares WHERE rnc_id = ? AND shared_with_user_id = ? LIMIT 1', (rnc_id, session['user_id']))
            is_shared_with_user = cur_shared.fetchone() is not None
        except Exception as e:
            logger.error(f"Erro ao verificar compartilhamento: {e}")
            is_shared_with_user = False
        
        # LOGS DETALHADOS PARA DEBUG
        logger.info(f"=== VERIFICAÇÃO DE PERMISSÕES PARA RESPONDER RNC {rnc_id} ===")
        logger.info(f"User ID: {session.get('user_id')}")
        logger.info(f"RNC Owner ID: {rnc_data[8]}")
        logger.info(f"É criador? {user_is_creator}")
        logger.info(f"É admin? {has_admin}")
        logger.info(f"Pode responder (reply_rncs)? {can_reply}")
        logger.info(f"Foi compartilhado? {is_shared_with_user}")
        logger.info(f"Permissões do usuário: {session.get('user_role', 'unknown')}")
        
        # PERMISSÕES SIMPLIFICADAS: Admin, criador, quem pode responder ou compartilhado
        if not (has_admin or user_is_creator or can_reply or is_shared_with_user):
            logger.warning(f"âŒ ACESSO NEGADO - Nenhuma permissÃ£o vÃ¡lida encontrada")
            logger.warning(f"   User: {session.get('user_name')} (ID: {session.get('user_id')})")
            logger.warning(f"   Role: {session.get('user_role')}")
            logger.warning(f"   Department: {session.get('user_department')}")
            return jsonify({'success': False, 'message': 'Acesso negado: você não tem permissão para responder este RNC'}), 403
        
        logger.info(f"âœ… ACESSO PERMITIDO para responder RNC {rnc_id}")

        data = request.get_json() or {}
        try:
            cur_cols = conn.cursor()
            cur_cols.execute('PRAGMA table_info(rncs)')
            col_names = [row[1] for row in cur_cols.fetchall()]
        except Exception:
            col_names = []
        current = {}
        try:
            if col_names and isinstance(rnc_data, (tuple, list)):
                current = dict(zip(col_names, rnc_data))
        except Exception:
            current = {}

        def get_bool(key):
            v = data.get(key, current.get(key))
            if isinstance(v, bool):
                return 1 if v else 0
            try:
                return 1 if str(v).strip().lower() in ('1','true','on','yes','y') else 0
            except Exception:
                return 0

        cursor.execute('SELECT signature_inspection_name, signature_engineering_name, signature_inspection2_name FROM rncs WHERE id = ?', (rnc_id,))
        current_sign = cursor.fetchone() or (None, None, None)
        new_sign = (
            data.get('signature_inspection_name', current_sign[0] or ''),
            data.get('signature_engineering_name', current_sign[1] or ''),
            data.get('signature_inspection2_name', current_sign[2] or '')
        )
        if not any(s and s != 'NOME' for s in new_sign):
            return jsonify({'success': False, 'message': 'Ã‰ obrigatÃ³rio preencher pelo menos uma assinatura!'}), 400

        disposition_usar = get_bool('disposition_usar')
        disposition_retrabalhar = get_bool('disposition_retrabalhar')
        disposition_rejeitar = get_bool('disposition_rejeitar')
        disposition_sucata = get_bool('disposition_sucata')
        disposition_devolver_estoque = get_bool('disposition_devolver_estoque')
        disposition_devolver_fornecedor = get_bool('disposition_devolver_fornecedor')
        inspection_aprovado = get_bool('inspection_aprovado')
        inspection_reprovado = get_bool('inspection_reprovado')
        inspection_ver_rnc = data.get('inspection_ver_rnc', current.get('inspection_ver_rnc', ''))
        instruction_retrabalho = data.get('instruction_retrabalho', current.get('instruction_retrabalho', ''))
        cause_rnc = data.get('cause_rnc', current.get('cause_rnc', ''))
        action_rnc = data.get('action_rnc', current.get('action_rnc', ''))

        # Usar descrição como fallback para título se vazio
        new_title = data.get('title') or current.get('title', '')
        new_description = data.get('description', current.get('description', ''))
        if not new_title and new_description:
            new_title = new_description[:100]
        
        cursor.execute('''
            UPDATE rncs 
            SET title = ?, description = ?, equipment = ?, client = ?, 
                priority = ?, status = ?, updated_at = CURRENT_TIMESTAMP,
                assigned_user_id = ?,
                price = ?,
                price_note = COALESCE(?, price_note),
                signature_inspection_name = ?, signature_engineering_name = ?, signature_inspection2_name = ?,
                signature_inspection_date = COALESCE(NULLIF(?, ''), signature_inspection_date),
                signature_engineering_date = COALESCE(NULLIF(?, ''), signature_engineering_date),
                signature_inspection2_date = COALESCE(NULLIF(?, ''), signature_inspection2_date),
                conjunto = ?, modelo = ?, description_drawing = ?, quantity = ?, material = ?,
                purchase_order = ?, responsavel = ?, inspetor = ?, area_responsavel = ?, setor = ?,
                mp = ?, revision = ?, position = ?, cv = ?, drawing = ?,
                disposition_usar = ?, disposition_retrabalhar = ?, disposition_rejeitar = ?, disposition_sucata = ?,
                disposition_devolver_estoque = ?, disposition_devolver_fornecedor = ?,
                inspection_aprovado = ?, inspection_reprovado = ?, inspection_ver_rnc = ?,
                instruction_retrabalho = ?, cause_rnc = ?, action_rnc = ?
            WHERE id = ?
        ''', (
            new_title,
            new_description,
            data.get('equipment', current.get('equipment','')),
            data.get('client', current.get('client','')),
            data.get('priority', current.get('priority','Média')),
            data.get('status', current.get('status','Pendente')),
            data.get('assigned_user_id', current.get('assigned_user_id')),
            float(data.get('price') or current.get('price') or 0),
            data.get('price_note', current.get('price_note','')),
            new_sign[0],
            new_sign[1],
            new_sign[2],
            data.get('signature_inspection_date') or current.get('signature_inspection_date'),
            data.get('signature_engineering_date') or current.get('signature_engineering_date'),
            data.get('signature_inspection2_date') or current.get('signature_inspection2_date'),
            data.get('conjunto', current.get('conjunto','')),
            data.get('modelo', current.get('modelo','')),
            data.get('description_drawing', current.get('description_drawing','')),
            data.get('quantity', current.get('quantity','')),
            data.get('material', current.get('material','')),
            data.get('purchase_order', current.get('purchase_order','')),
            data.get('responsavel', current.get('responsavel','')),
            data.get('inspetor', current.get('inspetor','')),
            data.get('area_responsavel', current.get('area_responsavel','')),
            data.get('setor', current.get('setor','')),
            data.get('mp', current.get('mp','')),
            data.get('revision', current.get('revision','')),
            data.get('position', current.get('position','')),
            data.get('cv', current.get('cv','')),
            data.get('drawing', current.get('drawing','')),
            disposition_usar,
            disposition_retrabalhar,
            disposition_rejeitar,
            disposition_sucata,
            disposition_devolver_estoque,
            disposition_devolver_fornecedor,
            inspection_aprovado,
            inspection_reprovado,
            inspection_ver_rnc,
            instruction_retrabalho,
            cause_rnc,
            action_rnc,
            rnc_id
        ))
        affected_rows = cursor.rowcount
        conn.commit()
        conn.close()

        clear_rnc_cache()
        try:
            keys_to_remove = []
            for key in list(query_cache.keys()):
                if key.startswith('rncs_list_') or key.startswith('charts_'):
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                del query_cache[key]
        except Exception:
            pass
        
        # ============================================
        # ENVIO DE NOTIFICAÇÕES DE ATUALIZAÇÃO (SocketIO)
        # ============================================
        try:
            from flask import current_app
            socketio = current_app.extensions.get('socketio')
            
            if socketio:
                # Buscar informações da RNC e do editor
                conn_notify = sqlite3.connect(DB_PATH)
                cursor_notify = conn_notify.cursor()
                
                cursor_notify.execute('SELECT name FROM users WHERE id = ?', (session['user_id'],))
                editor_info = cursor_notify.fetchone()
                editor_name = editor_info[0] if editor_info else 'Usuário'
                
                cursor_notify.execute('SELECT rnc_number, title FROM rncs WHERE id = ?', (rnc_id,))
                rnc_info = cursor_notify.fetchone()
                rnc_number = rnc_info[0] if rnc_info else f'RNC-{rnc_id}'
                rnc_title = rnc_info[1] if rnc_info else 'RNC'
                
                # Buscar todos os usuários interessados (criador, compartilhados, atribuídos)
                cursor_notify.execute('''
                    SELECT DISTINCT user_id FROM rncs WHERE id = ?
                    UNION
                    SELECT DISTINCT shared_with_user_id FROM rnc_shares WHERE rnc_id = ?
                    UNION
                    SELECT DISTINCT assigned_user_id FROM rncs WHERE id = ? AND assigned_user_id IS NOT NULL
                ''', (rnc_id, rnc_id, rnc_id))
                
                interested_users = [row[0] for row in cursor_notify.fetchall()]
                conn_notify.close()
                
                # Enviar notificação para cada usuário interessado (exceto o editor)
                for user_id in interested_users:
                    if user_id != session['user_id']:
                        notification_data = {
                            'type': 'rnc_updated',
                            'title': ' RNC Atualizada',
                            'message': f'{editor_name} editou a RNC {rnc_number}',
                            'rnc_id': rnc_id,
                            'rnc_number': rnc_number,
                            'rnc_title': rnc_title,
                            'user_name': editor_name,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Emitir evento SocketIO
                        logger.info(f" ========================================")
                        logger.info(f" ENVIANDO NOTIFICAÇÃO DE ATUALIZAÇÃO PARA USUÁRIO {user_id}")
                        logger.info(f" Room: user_{user_id}")
                        logger.info(f" Dados: {notification_data}")
                        
                        socketio.emit('rnc_updated', notification_data, room=f'user_{user_id}')
                        
                        logger.info(f" Notificação de atualização emitida com sucesso!")
                        logger.info(f" ========================================")
                        
        except Exception as e:
            logger.error(f" Erro ao enviar notificação de atualização: {e}")
        
        return jsonify({'success': True, 'message': 'RNC atualizado com sucesso!', 'affected_rows': affected_rows})
    except Exception as e:
        logger.error(f"Erro ao atualizar RNC {rnc_id}: {e}")
        return jsonify({'success': False, 'message': f'Erro interno: {str(e)}'}), 500


@rnc.route('/api/rnc/<int:rnc_id>/finalize', methods=['POST'])
@csrf_protect()
def finalize_rnc(rnc_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.permissions import has_permission
        from services.cache import clear_rnc_cache
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM rncs WHERE id = ? AND is_deleted = 0', (rnc_id,))
        rnc_row = cursor.fetchone()
        if not rnc_row:
            conn.close()
            return jsonify({'success': False, 'message': 'RNC não encontrado'}), 404
        if not isinstance(rnc_row, (sqlite3.Row, tuple, list)):
            logger.error(f"Erro: rnc não é uma tupla/lista: {type(rnc_row)} - {rnc_row}")
            conn.close()
            return jsonify({'success': False, 'message': 'Erro interno do sistema'}), 500

        # VALIDAÇÃO DE CAMPOS OBRIGATÓRIOS
        missing_fields = []
        
        # Converter Row para dict
        rnc_dict = dict(rnc_row)
        
        # 1. Campos basicos obrigatorios
        if not rnc_dict.get('title') or str(rnc_dict.get('title', '')).strip() == '':
            missing_fields.append('Titulo da Nao Conformidade')
        
        if not rnc_dict.get('description') or str(rnc_dict.get('description', '')).strip() == '':
            missing_fields.append('Descricao da Nao Conformidade')
        
        if not rnc_dict.get('equipment') or str(rnc_dict.get('equipment', '')).strip() == '':
            missing_fields.append('Equipamento')
        
        if not rnc_dict.get('client') or str(rnc_dict.get('client', '')).strip() == '':
            missing_fields.append('Cliente')
        
        if not rnc_dict.get('priority') or str(rnc_dict.get('priority', '')).strip() == '':
            missing_fields.append('Prioridade')
        
        # 2. Pelo menos uma disposicao deve estar marcada
        has_disposition = (
            rnc_dict.get('disposition_usar') or 
            rnc_dict.get('disposition_retrabalhar') or 
            rnc_dict.get('disposition_rejeitar') or 
            rnc_dict.get('disposition_sucata') or 
            rnc_dict.get('disposition_devolver_estoque') or 
            rnc_dict.get('disposition_devolver_fornecedor')
        )
        if not has_disposition:
            missing_fields.append('Disposicao do Material (selecione ao menos uma opcao)')
        
        # 3. Assinaturas obrigatorias (nome e data)
        if not rnc_dict.get('signature_inspection_name') or str(rnc_dict.get('signature_inspection_name', '')).strip() == '':
            missing_fields.append('Assinatura Inspecao - Nome')
        
        if not rnc_dict.get('signature_inspection_date') or str(rnc_dict.get('signature_inspection_date', '')).strip() == '':
            missing_fields.append('Assinatura Inspecao - Data')
        
        # Se houver campos faltando, retornar erro com lista
        if missing_fields:
            conn.close()
            return jsonify({
                'success': False, 
                'message': 'RNC não pode ser finalizada. Existem campos obrigatórios não preenchidos.',
                'missing_fields': missing_fields
            }), 400

        # Verificação de permissão
        user_id = session['user_id']
        cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({'success': False, 'message': 'Usuário não encontrado'}), 404
        user_role = user['role'] if isinstance(user, sqlite3.Row) else user[0]
        rnc_creator_id = rnc_dict.get('user_id')
        is_creator = (user_id == rnc_creator_id)
        if not is_creator and user_role != 'admin':
            conn.close()
            return jsonify({'success': False, 'message': 'Apenas o criador do RNC pode finalizá-lo'}), 403

        # Finalizar RNC
        cursor.execute('''
            UPDATE rncs 
            SET status = 'Finalizado', finalized_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (rnc_id,))
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'message': 'Erro ao finalizar RNC'}), 500
        conn.commit()
        conn.close()
        clear_rnc_cache()
        return jsonify({'success': True, 'message': 'RNC finalizado com sucesso!'})
    except Exception as e:
        logger.error(f"Erro ao finalizar RNC: {e}")
        return jsonify({'success': False, 'message': f'Erro interno: {str(e)}'}), 500


@rnc.route('/api/rnc/<int:rnc_id>/reply', methods=['POST'])
@csrf_protect()
def reply_rnc_api(rnc_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.permissions import has_permission
        from services.cache import clear_rnc_cache
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, user_id, assigned_user_id, status FROM rncs WHERE id = ? AND is_deleted = 0', (rnc_id,))
        rnc = cursor.fetchone()
        if not rnc:
            conn.close()
            return jsonify({'success': False, 'message': 'RNC não encontrada'}), 404
        rnc_creator_id = rnc[1]
        rnc_assigned_id = rnc[2]
        user_id = session['user_id']
        is_creator = str(user_id) == str(rnc_creator_id)
        is_admin = has_permission(user_id, 'admin_access')
        is_assigned = (rnc_assigned_id is not None and str(user_id) == str(rnc_assigned_id))
        can_reply = has_permission(user_id, 'reply_rncs')
        # Novo: permitir responder se compartilhado com o usuário
        shared_can_reply = False
        try:
            cur_share = conn.cursor()
            cur_share.execute('SELECT 1 FROM rnc_shares WHERE rnc_id = ? AND shared_with_user_id = ? LIMIT 1', (rnc_id, user_id))
            shared_can_reply = cur_share.fetchone() is not None
        except Exception:
            shared_can_reply = False
        if not (is_creator or is_assigned or is_admin or can_reply or shared_can_reply):
            conn.close()
            return jsonify({'success': False, 'message': 'Sem permissão para responder esta RNC'}), 403
        cursor.execute('''
            UPDATE rncs
               SET status = 'Pendente',
                   finalized_at = NULL,
                   updated_at = CURRENT_TIMESTAMP,
                   assigned_user_id = ?
             WHERE id = ?
        ''', (user_id, rnc_id))
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'message': 'Nenhuma alteração realizada'}), 400
        conn.commit()
        conn.close()
        clear_rnc_cache()
        return jsonify({'success': True, 'message': 'RNC reenviada com sucesso'})
    except Exception as e:
        try:
            conn.close()
        except Exception:
            pass
        return jsonify({'success': False, 'message': f'Erro interno: {str(e)}'}), 500


@rnc.route('/api/rnc/<int:rnc_id>/delete', methods=['DELETE'])
@csrf_protect()
def delete_rnc(rnc_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.cache import cache_lock, query_cache
        from services.permissions import has_permission
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, user_id FROM rncs WHERE id = ?', (rnc_id,))
        rnc = cursor.fetchone()
        if not rnc:
            conn.close()
            return jsonify({'success': False, 'message': 'RNC não encontrado'}), 404
        # Permissão: apenas criador ou admin pode deletar
        creator_id = rnc[1]
        user_id = session['user_id']
        is_creator = str(user_id) == str(creator_id)
        is_admin = has_permission(user_id, 'admin_access')
        if not (is_creator or is_admin):
            conn.close()
            return jsonify({'success': False, 'message': 'Sem permissão para excluir este RNC'}), 403
        cursor.execute('DELETE FROM rncs WHERE id = ?', (rnc_id,))
        cursor.execute('DELETE FROM rnc_shares WHERE rnc_id = ?', (rnc_id,))
        cursor.execute('DELETE FROM chat_messages WHERE rnc_id = ?', (rnc_id,))
        conn.commit()
        conn.close()
        with cache_lock:
            keys_to_remove = [key for key in list(query_cache.keys()) if 'rncs_list_' in key or 'rnc_' in key or 'charts_' in key]
            for key in keys_to_remove:
                del query_cache[key]
        logger.info(f"RNC {rnc_id} excluído definitivamente por usuário {session['user_id']}")
        return jsonify({'success': True, 'message': 'RNC excluído definitivamente.', 'cache_cleared': True})
    except Exception as e:
        logger.error(f"Erro ao deletar RNC: {e}")
        return jsonify({'success': False, 'message': f'Erro interno: {str(e)}'}), 500


@rnc.route('/api/rnc/<int:rnc_id>/permanent-delete', methods=['DELETE', 'POST', 'OPTIONS'])
# CSRF desabilitado para permitir AJAX com credentials na porta 5001
# @csrf_protect()
def permanent_delete_rnc(rnc_id):
    """Apagar RNC permanentemente do banco de dados (ADMIN ONLY)"""
    logger.info(f"🗑️ Delete request - RNC ID: {rnc_id}, Method: {request.method}, Session: {session.get('user_id', 'NONE')}")
    
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        response = jsonify({'success': True})
        response.headers.add('Access-Control-Allow-Methods', 'DELETE, POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        return response, 200
    
    if 'user_id' not in session:
        logger.warning(f"❌ Delete NEGADO - Sem sessão para RNC {rnc_id}")
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    
    try:
        from services.cache import cache_lock, query_cache
        from services.permissions import has_permission
        
        user_id = session['user_id']
        
        # Verificar permissão de admin
        has_perm = has_permission(user_id, 'permanent_delete_rnc')
        is_admin = has_permission(user_id, 'admin_access')
        
        if not (has_perm or is_admin):
            return jsonify({
                'success': False, 
                'message': 'Sem permissão. Apenas administradores podem apagar RNCs permanentemente.'
            }), 403
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verificar se RNC existe e está finalizado
        cursor.execute('SELECT id, rnc_number, status FROM rncs WHERE id = ?', (rnc_id,))
        rnc = cursor.fetchone()
        
        if not rnc:
            conn.close()
            return jsonify({'success': False, 'message': 'RNC não encontrado'}), 404
        
        rnc_number = rnc[1]
        rnc_status = rnc[2]
        
        # Apenas permitir apagar RNCs finalizadas
        if rnc_status != 'Finalizado':
            conn.close()
            return jsonify({
                'success': False, 
                'message': 'Apenas RNCs finalizadas podem ser apagadas permanentemente'
            }), 400
        
        # Apagar permanentemente do banco
        cursor.execute('DELETE FROM rncs WHERE id = ?', (rnc_id,))
        cursor.execute('DELETE FROM rnc_shares WHERE rnc_id = ?', (rnc_id,))
        cursor.execute('DELETE FROM chat_messages WHERE rnc_id = ?', (rnc_id,))
        
        conn.commit()
        conn.close()
        
        # Limpar cache
        with cache_lock:
            keys_to_remove = [key for key in list(query_cache.keys()) 
                            if 'rncs_list_' in key or 'rnc_' in key or 'charts_' in key]
            for key in keys_to_remove:
                del query_cache[key]
        
        logger.info(f"RNC {rnc_number} (ID: {rnc_id}) APAGADO PERMANENTEMENTE por admin {user_id}")
        
        return jsonify({
            'success': True, 
            'message': f'RNC {rnc_number} apagado permanentemente do banco de dados.'
        })
        
    except Exception as e:
        logger.error(f"Erro ao apagar RNC permanentemente: {e}")
        return jsonify({'success': False, 'message': f'Erro interno: {str(e)}'}), 500


@rnc.route('/api/rnc/<int:rnc_id>/renumber-v2', methods=['POST', 'OPTIONS'])
# CSRF desabilitado para permitir AJAX com credentials na porta 5001
# @csrf_protect()
def renumber_rnc_v2(rnc_id):
    """Renumerar uma RNC finalizada (ADMIN ONLY) - Versão 2"""
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        response = jsonify({'success': True})
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        return response, 200
    
    logger.info(f"Requisição renumber-v2 recebida - RNC ID: {rnc_id}, Method: {request.method}")
    
    if 'user_id' not in session:
        logger.warning(f"Tentativa de renumeração sem autenticação - RNC ID: {rnc_id}")
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    
    try:
        from services.cache import cache_lock, query_cache
        from services.permissions import has_permission
        
        user_id = session['user_id']
        data = request.get_json()
        new_number = data.get('new_number', '').strip()
        
        if not new_number:
            return jsonify({'success': False, 'message': 'Novo número não fornecido'}), 400
        
        # Verificar permissão de admin
        has_perm = has_permission(user_id, 'renumber_rnc')
        is_admin = has_permission(user_id, 'admin_access')
        
        if not (has_perm or is_admin):
            return jsonify({
                'success': False, 
                'message': 'Sem permissão. Apenas administradores podem renumerar RNCs.'
            }), 403
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verificar se RNC existe
        cursor.execute('SELECT id, rnc_number, status FROM rncs WHERE id = ?', (rnc_id,))
        rnc = cursor.fetchone()
        
        if not rnc:
            conn.close()
            return jsonify({'success': False, 'message': 'RNC não encontrado'}), 404
        
        old_number = rnc[1]
        rnc_status = rnc[2]
        
        # Verificar se o novo número já existe
        cursor.execute('SELECT id FROM rncs WHERE rnc_number = ? AND id != ?', (new_number, rnc_id))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            return jsonify({
                'success': False, 
                'message': f'O número {new_number} já está em uso por outra RNC'
            }), 400
        
        # Atualizar número
        cursor.execute('UPDATE rncs SET rnc_number = ? WHERE id = ?', (new_number, rnc_id))
        conn.commit()
        conn.close()
        
        # Limpar cache
        with cache_lock:
            keys_to_remove = [key for key in list(query_cache.keys()) 
                            if 'rncs_list_' in key or 'rnc_' in key or 'charts_' in key]
            for key in keys_to_remove:
                del query_cache[key]
        
        logger.info(f"RNC {old_number} RENUMERADA para {new_number} por admin {user_id}")
        
        return jsonify({
            'success': True, 
            'message': f'RNC renumerada de {old_number} para {new_number}',
            'old_number': old_number,
            'new_number': new_number
        })
        
    except Exception as e:
        logger.error(f"Erro ao renumerar RNC: {e}")
        return jsonify({'success': False, 'message': f'Erro interno: {str(e)}'}), 500


@rnc.route('/api/rnc/<int:rnc_id>/share', methods=['POST'])
@csrf_protect()
def share_rnc(rnc_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.permissions import has_permission
        from services.rnc import share_rnc_with_user
        data = request.get_json()
        shared_with_user_ids = data.get('shared_with_user_ids', [])
        permission_level = data.get('permission_level', 'view')
        cursor = sqlite3.connect(DB_PATH).cursor()
        cursor.execute('SELECT * FROM rncs WHERE id = ?', (rnc_id,))
        rnc_data = cursor.fetchone()
        cursor.connection.close()
        if rnc_data is None:
            return jsonify({'success': False, 'message': 'RNC não encontrado'}), 404
        user_id_index = 8
        if len(rnc_data) <= user_id_index:
            return jsonify({'success': False, 'message': 'Dados do RNC incompletos'}), 400
        is_creator = (rnc_data[user_id_index] == session['user_id'])
        has_admin_permission = has_permission(session['user_id'], 'view_all_rncs')
        if not is_creator and not has_admin_permission:
            return jsonify({'success': False, 'message': 'Sem permissão para compartilhar esta RNC'}), 403
        success_count = 0
        for user_id in shared_with_user_ids:
            if share_rnc_with_user(rnc_id, session['user_id'], user_id, permission_level):
                success_count += 1
        if success_count > 0:
            return jsonify({'success': True, 'message': f'RNC compartilhada com {success_count} usuário(s) com sucesso!'})
        else:
            return jsonify({'success': False, 'message': 'Erro ao compartilhar RNC'}), 500
    except Exception as e:
        logger.error(f"Erro ao compartilhar RNC {rnc_id}: {e}")
        return jsonify({'success': False, 'message': 'Erro interno do sistema'}), 500


@rnc.route('/api/rnc/<int:rnc_id>/shared-users', methods=['GET'])
def get_shared_users(rnc_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.rnc import can_user_access_rnc
        from services.db import get_db_connection, return_db_connection
        try:
            from services.pagination import parse_cursor_limit, compute_window  # type: ignore
        except Exception:
            import importlib
            pagination = importlib.import_module('services.pagination')
            parse_cursor_limit = getattr(pagination, 'parse_cursor_limit')
            compute_window = getattr(pagination, 'compute_window')
        if not can_user_access_rnc(session['user_id'], rnc_id):
            return jsonify({'success': False, 'message': 'Sem permissão para acessar esta RNC'}), 403
        cursor_id, limit = parse_cursor_limit(request, default_limit=20, max_limit=200)

        conn = get_db_connection()
        cur = conn.cursor()
        where_extra = ""
        params = [rnc_id]
        # Use rs.id (share row id) as cursor anchor for deterministic pagination
        if cursor_id is not None:
            where_extra = " AND rs.id < ?"
            params.append(cursor_id)
        params.append(limit + 1)
        cur.execute(
            '''
            SELECT rs.id, rs.shared_with_user_id, rs.permission_level, u.name, u.email
              FROM rnc_shares rs
              JOIN users u ON rs.shared_with_user_id = u.id
             WHERE rs.rnc_id = ?
                   ''' + where_extra + '''
             ORDER BY rs.id DESC
             LIMIT ?
            ''', tuple(params)
        )
        rows = cur.fetchall()
        # id_index=0 now (rs.id)
        rows, has_more, next_cursor = compute_window(rows, limit, id_index=0)
        return_db_connection(conn)

        shared_users_list = [
            {
                'user_id': user_id,
                'permission_level': perm,
                'name': name,
                'email': email,
            }
            for (_row_id, user_id, perm, name, email) in rows
        ]
        return jsonify({'success': True, 'shared_users': shared_users_list, 'limit': limit, 'next_cursor': next_cursor, 'has_more': has_more})
    except Exception as e:
        logger.error(f"Erro ao buscar usuários compartilhados da RNC {rnc_id}: {e}")
        return jsonify({'success': False, 'message': 'Erro interno do sistema'}), 500


# Debug endpoints (mantidos no blueprint RNC)
@rnc.route('/api/debug/rnc-count')
def debug_rnc_count():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.db import get_db_connection, return_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM rncs')
        total = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM rncs WHERE status = "Finalizado"')
        finalizados = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM rncs WHERE (is_deleted = 0 OR is_deleted IS NULL) AND status = "Finalizado"')
        finalizados_ativos = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM rncs WHERE (is_deleted = 0 OR is_deleted IS NULL) AND status != "Finalizado"')
        ativos = cursor.fetchone()[0]
        return_db_connection(conn)
        return jsonify({'success': True, 'counts': {'total': total, 'finalizados': finalizados, 'finalizados_ativos': finalizados_ativos, 'ativos': ativos}})
    except Exception as e:
        logger.error(f"Erro no debug: {e}")
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500


@rnc.route('/api/debug/rnc-count-by-year')
def debug_rnc_count_by_year():
    """
    Retorna contagens de RNCs agrupadas por ano (global) e contagens visíveis ao usuário
    (para ajudar a diagnosticar discrepâncias, ex: RNCs de 2024 não aparecendo na UI).
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.db import get_db_connection, return_db_connection
        conn = get_db_connection()
        cur = conn.cursor()

        # 1) Contagens globais por ano e status (finalized vs others)
        cur.execute("""
            SELECT COALESCE(strftime('%Y', finalized_at), strftime('%Y', created_at)) as year,
                   status,
                   COUNT(*) as cnt
            FROM rncs
            GROUP BY year, status
            ORDER BY year DESC
        """)
        rows = cur.fetchall()
        global_by_year = {}
        for year, status, cnt in rows:
            y = year or 'unknown'
            global_by_year.setdefault(y, {})
            global_by_year[y][status or 'unknown'] = cnt

        # 2) Contagens de finalizados visíveis para o usuário por ano
        user_id = session['user_id']
        cur.execute("""
            SELECT COALESCE(strftime('%Y', COALESCE(finalized_at, created_at)), strftime('%Y', created_at)) as year,
                   COUNT(*) as cnt
            FROM rncs r
            WHERE (r.is_deleted = 0 OR r.is_deleted IS NULL)
              AND r.status = 'Finalizado'
              AND (
                    r.user_id = ?
                    OR r.assigned_user_id = ?
                    OR EXISTS (SELECT 1 FROM rnc_shares rs WHERE rs.rnc_id = r.id AND rs.shared_with_user_id = ?)
                  )
            GROUP BY year
            ORDER BY year DESC
        """, (user_id, user_id, user_id))
        vis_rows = cur.fetchall()
        visible_finalized_by_year = { (r[0] or 'unknown'): r[1] for r in vis_rows }

        return_db_connection(conn)
        return jsonify({'success': True, 'global_by_year': global_by_year, 'visible_finalized_by_year': visible_finalized_by_year})
    except Exception as e:
        logger.error(f"Erro no debug rnc-count-by-year: {e}")
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500


@rnc.route('/api/public/finalized-monthly')
def public_finalized_monthly():
    """Public endpoint: returns monthly counts (YYYY-MM) for RNCs with status 'Finalizado'.
    Optional query params:
      - year=YYYY (filter by year)
      - setor=NAME (filter by setor or area_responsavel contains NAME)
    This endpoint is intentionally public (no session check) because it's used for dashboard-only aggregates.
    """
    try:
        from services.db import get_db_connection, return_db_connection
        conn = get_db_connection()
        cur = conn.cursor()

        year = (request.args.get('year') or '').strip()
        setor = (request.args.get('setor') or '').strip()

        where = ["status = 'Finalizado'"]
        params = []

        if year:
            # match by finalized_at or created_at year
            where.append("COALESCE(strftime('%Y', finalized_at), strftime('%Y', created_at)) = ?")
            params.append(year)

        if setor:
            where.append("(LOWER(TRIM(setor)) LIKE LOWER(TRIM(?)) OR LOWER(TRIM(area_responsavel)) LIKE LOWER(TRIM(?)))")
            params.extend([f'%{setor}%', f'%{setor}%'])

        sql = f"SELECT COALESCE(strftime('%Y-%m', finalized_at), strftime('%Y-%m', created_at)) as month, COUNT(*) as cnt FROM rncs WHERE {' AND '.join(where)} GROUP BY month ORDER BY month ASC"
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()

        monthly = [{'month': r[0] or '', 'count': r[1]} for r in rows]

        return_db_connection(conn)
        return jsonify({'success': True, 'monthly_trend': monthly})
    except Exception as e:
        logger.error(f"Erro em public_finalized_monthly: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@rnc.route('/api/debug/user-rncs')
def debug_user_rncs():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.db import get_db_connection, return_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = session['user_id']
        cursor.execute('SELECT COUNT(*) FROM rncs WHERE user_id = ?', (user_id,))
        created_by_user = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM rncs WHERE assigned_user_id = ?', (user_id,))
        assigned_to_user = cursor.fetchone()[0]
        cursor.execute('''SELECT COUNT(*) FROM rncs 
                         WHERE (is_deleted = 0 OR is_deleted IS NULL) 
                         AND status != "Finalizado" 
                         AND (user_id = ? OR assigned_user_id = ?)''', (user_id, user_id))
        active_total = cursor.fetchone()[0]
        cursor.execute('''SELECT COUNT(*) FROM rncs 
                         WHERE (is_deleted = 0 OR is_deleted IS NULL) 
                         AND status = "Finalizado" 
                         AND (user_id = ? OR assigned_user_id = ?)''', (user_id, user_id))
        finalized_total = cursor.fetchone()[0]
        cursor.execute('''SELECT id, rnc_number, title, status, user_id, assigned_user_id 
                         FROM rncs 
                         WHERE (user_id = ? OR assigned_user_id = ?) 
                         ORDER BY id DESC LIMIT 5''', (user_id, user_id))
        examples = cursor.fetchall()
        return_db_connection(conn)
        return jsonify({
            'success': True,
            'user_id': user_id,
            'user_name': session.get('user_name', 'N/A'),
            'counts': {
                'created_by_user': created_by_user,
                'assigned_to_user': assigned_to_user,
                'active_total': active_total,
                'finalized_total': finalized_total
            },
            'examples': [
                {
                    'id': ex[0],
                    'rnc_number': ex[1],
                    'title': ex[2],
                    'status': ex[3],
                    'is_creator': ex[4] == user_id,
                    'is_assigned': ex[5] == user_id
                }
                for ex in examples
            ]
        })
    except Exception as e:
        logger.error(f"Erro no debug de usuário: {e}")
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500


@rnc.route('/api/debug/user-shares')
def debug_user_shares():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.db import get_db_connection, return_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = session['user_id']
        cursor.execute('''
            SELECT rs.rnc_id, r.rnc_number, r.title, r.status, 
                   u.name as shared_by, rs.permission_level, rs.created_at
            FROM rnc_shares rs
            JOIN rncs r ON rs.rnc_id = r.id
            LEFT JOIN users u ON rs.shared_by_user_id = u.id
            WHERE rs.shared_with_user_id = ?
            ORDER BY rs.created_at DESC LIMIT 10
        ''', (user_id,))
        shared_with_user = cursor.fetchall()
        cursor.execute('''
            SELECT rs.rnc_id, r.rnc_number, r.title, r.status, 
                   u.name as shared_with, rs.permission_level, rs.created_at
            FROM rnc_shares rs
            JOIN rncs r ON rs.rnc_id = r.id
            LEFT JOIN users u ON rs.shared_with_user_id = u.id
            WHERE rs.shared_by_user_id = ?
            ORDER BY rs.created_at DESC LIMIT 10
        ''', (user_id,))
        shared_by_user = cursor.fetchall()
        cursor.execute('SELECT COUNT(*) FROM rnc_shares WHERE shared_with_user_id = ?', (user_id,))
        total_shared_with = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM rnc_shares WHERE shared_by_user_id = ?', (user_id,))
        total_shared_by = cursor.fetchone()[0]
        return_db_connection(conn)
        return jsonify({
            'success': True,
            'user_id': user_id,
            'user_name': session.get('user_name', 'N/A'),
            'totals': {
                'shared_with_me': total_shared_with,
                'shared_by_me': total_shared_by
            },
            'shared_with_me': [
                {
                    'rnc_id': share[0],
                    'rnc_number': share[1],
                    'title': share[2],
                    'status': share[3],
                    'shared_by': share[4],
                    'permission': share[5],
                    'shared_at': share[6]
                }
                for share in shared_with_user
            ],
            'shared_by_me': [
                {
                    'rnc_id': share[0],
                    'rnc_number': share[1],
                    'title': share[2],
                    'status': share[3],
                    'shared_with': share[4],
                    'permission': share[5],
                    'shared_at': share[6]
                }
                for share in shared_by_user
            ]
        })
    except Exception as e:
        logger.error(f"Erro no debug de compartilhamentos: {e}")
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500


@rnc.route('/api/debug/rnc-signatures/<int:rnc_id>')
def debug_rnc_signatures(rnc_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'}), 401
    try:
        from services.db import get_db_connection, return_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, rnc_number, title,
                   signature_inspection_name, signature_engineering_name, signature_inspection2_name,
                   signature_inspection_date, signature_engineering_date, signature_inspection2_date
            FROM rncs 
            WHERE id = ?
        ''', (rnc_id,))
        rnc_data = cursor.fetchone()
        return_db_connection(conn)
        if not rnc_data:
            return jsonify({'success': False, 'message': 'RNC não encontrada'}), 404
        return jsonify({
            'success': True,
            'rnc_id': rnc_id,
            'rnc_number': rnc_data[1],
            'title': rnc_data[2],
            'signatures': {
                'inspection_name': rnc_data[3],
                'engineering_name': rnc_data[4],
                'inspection2_name': rnc_data[5],
                'inspection_date': rnc_data[6],
                'engineering_date': rnc_data[7],
                'inspection2_date': rnc_data[8]
            },
            'debug_info': {
                'inspection_empty': not rnc_data[3] or rnc_data[3] == 'NOME',
                'engineering_empty': not rnc_data[4] or rnc_data[4] == 'NOME',
                'inspection2_empty': not rnc_data[5] or rnc_data[5] == 'NOME'
            }
        })
    except Exception as e:
        logger.error(f"Erro no debug de assinaturas: {e}")
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'}), 500




# ============================================
# ROTAS DA API DE VALORES/HORA
# ============================================

@rnc.route('/api/valores-hora/list', methods=['GET'])
def list_valores_hora():
    """Lista todos os valores/hora disponíveis"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Não autenticado'}), 401
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Buscar todos os valores ordenados por setor e código
        cursor.execute("""
            SELECT id, codigo, setor, descricao, valor_hora, created_at, updated_at
            FROM valores_hora
            ORDER BY setor, codigo
        """)
        
        valores = []
        for row in cursor.fetchall():
            valores.append({
                'id': row[0],
                'codigo': row[1],
                'setor': row[2],
                'descricao': row[3],
                'valor_hora': row[4],
                'created_at': row[5],
                'updated_at': row[6]
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'valores': valores,
            'total': len(valores)
        })
        
    except Exception as e:
        logger.error(f"Erro ao listar valores/hora: {e}")
        return jsonify({'success': False, 'message': 'Erro ao buscar valores'}), 500


@rnc.route('/api/valores-hora/save', methods=['POST'])
def save_valor_hora():
    """Salva um novo valor/hora"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Não autenticado'}), 401
        
        data = request.get_json(silent=True) or {}

        # Validações
        required_fields = ['codigo', 'setor', 'descricao', 'valor_hora']
        for field in required_fields:
            if not (data.get(field) or '').strip():
                return jsonify({'success': False, 'message': f'Campo {field} é obrigatório'}), 400

        # Normalizar número com vírgula/ponto e possíveis milhares
        raw_val = str(data.get('valor_hora')).strip()
        # Suporta: 1.234,56 | 1234,56 | 1,234.56 | 1234.56 | 1234
        if ',' in raw_val and '.' in raw_val:
            # Considera o último separador como decimal; remove o outro como milhar
            if raw_val.rfind(',') > raw_val.rfind('.'):
                norm_val = raw_val.replace('.', '').replace(',', '.')
            else:
                norm_val = raw_val.replace(',', '')
        elif ',' in raw_val:
            norm_val = raw_val.replace('.', '').replace(',', '.')
        else:
            # Já no padrão com ponto (ou inteiro)
            norm_val = raw_val.replace(',', '')

        try:
            parsed_valor = round(float(norm_val), 2)
        except Exception:
            return jsonify({'success': False, 'message': 'Valor por hora inválido'}), 400
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Verificar se código já existe
        cursor.execute('SELECT id FROM valores_hora WHERE codigo = ?', (data['codigo'],))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Código já existe'}), 400
        
        # Inserir novo valor
        cursor.execute("""
            INSERT INTO valores_hora (codigo, setor, descricao, valor_hora, created_at, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (
            data['codigo'],
            data['setor'],
            data['descricao'],
            parsed_valor
        ))
        
        valor_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f" Novo valor/hora criado: {data['codigo']} - {data['descricao']}")
        
        return jsonify({
            'success': True,
            'message': 'Valor salvo com sucesso',
            'id': valor_id
        })
        
    except Exception as e:
        logger.exception("Erro ao salvar valor/hora")
        # Expor mensagem para facilitar depuração no cliente (pode ser ajustado depois)
        return jsonify({'success': False, 'message': f'Erro ao salvar valor: {str(e)}'}), 500


@rnc.route('/api/valores-hora/update/<int:valor_id>', methods=['PUT'])
def update_valor_hora(valor_id):
    """Atualiza um valor/hora existente"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Não autenticado'}), 401
        
        data = request.get_json(silent=True) or {}
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Verificar se valor existe
        cursor.execute('SELECT id FROM valores_hora WHERE id = ?', (valor_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Valor não encontrado'}), 404
        
        # Normalizar valor_hora, se enviado
        val_to_store = None
        if 'valor_hora' in data and data.get('valor_hora') is not None:
            raw_val = str(data.get('valor_hora')).strip()
            if ',' in raw_val and '.' in raw_val:
                if raw_val.rfind(',') > raw_val.rfind('.'):
                    norm_val = raw_val.replace('.', '').replace(',', '.')
                else:
                    norm_val = raw_val.replace(',', '')
            elif ',' in raw_val:
                norm_val = raw_val.replace('.', '').replace(',', '.')
            else:
                norm_val = raw_val.replace(',', '')
            try:
                val_to_store = round(float(norm_val), 2)
            except Exception:
                return jsonify({'success': False, 'message': 'Valor por hora inválido'}), 400
        else:
            val_to_store = 0.0

        # Atualizar valor
        cursor.execute("""
            UPDATE valores_hora 
            SET descricao = ?, valor_hora = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (
            data.get('descricao'),
            val_to_store,
            valor_id
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f" Valor/hora atualizado: ID {valor_id}")
        
        return jsonify({
            'success': True,
            'message': 'Valor atualizado com sucesso'
        })
        
    except Exception as e:
        logger.error(f"Erro ao atualizar valor/hora: {e}")
        return jsonify({'success': False, 'message': 'Erro ao atualizar valor'}), 500


@rnc.route('/api/valores-hora/delete/<int:valor_id>', methods=['DELETE'])
def delete_valor_hora(valor_id):
    """Remove um valor/hora"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Não autenticado'}), 401
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Verificar se valor existe
        cursor.execute('SELECT codigo, descricao FROM valores_hora WHERE id = ?', (valor_id,))
        valor = cursor.fetchone()
        if not valor:
            conn.close()
            return jsonify({'success': False, 'message': 'Valor não encontrado'}), 404
        
        # Remover valor
        cursor.execute('DELETE FROM valores_hora WHERE id = ?', (valor_id,))
        
        conn.commit()
        conn.close()
        
        logger.info(f" Valor/hora removido: {valor[0]} - {valor[1]}")
        
        return jsonify({
            'success': True,
            'message': 'Valor removido com sucesso'
        })
        
    except Exception as e:
        logger.error(f"Erro ao remover valor/hora: {e}")
        return jsonify({'success': False, 'message': 'Erro ao remover valor'}), 500


@rnc.route('/api/valores-hora/setores', methods=['GET'])
def list_setores_valores():
    """Lista todos os setores disponíveis na tabela de valores"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Não autenticado'}), 401
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Buscar setores únicos
        cursor.execute("""
            SELECT DISTINCT setor, COUNT(*) as total
            FROM valores_hora
            GROUP BY setor
            ORDER BY setor
        """)
        
        setores = []
        for row in cursor.fetchall():
            setores.append({
                'nome': row[0],
                'total_itens': row[1]
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'setores': setores
        })
        
    except Exception as e:
        logger.error(f"Erro ao listar setores: {e}")
        return jsonify({'success': False, 'message': 'Erro ao buscar setores'}), 500
