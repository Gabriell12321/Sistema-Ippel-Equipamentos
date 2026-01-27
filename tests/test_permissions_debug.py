#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Teste para verificar permissões do usuário admin
"""

import requests
import sqlite3

# Configurações
BASE_URL = "http://localhost:5001"
from tests.test_config import TEST_EMAIL, TEST_PASSWORD
DB_PATH = "ippel_system.db"

def test_login():
    """Testa o login para obter sessão"""
    print("🔐 Testando login...")
    
    login_data = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/login", json=login_data)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("✅ Login realizado com sucesso!")
                return response.cookies
            else:
                print(f"❌ Login falhou: {data.get('message')}")
                return None
        else:
            print(f"❌ Erro no login: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Erro ao conectar com o servidor: {e}")
        return None

def check_user_permissions():
    """Verifica as permissões do usuário admin no banco de dados"""
    print("\n🔐 Verificando permissões do usuário admin...")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Buscar usuário admin
        cursor.execute("SELECT id, name, email, role FROM users WHERE email = ?", (TEST_EMAIL,))
        user = cursor.fetchone()
        
        if user:
            print(f"✅ Usuário encontrado: ID={user[0]}, Nome={user[1]}, Email={user[2]}, Role={user[3]}")
            
            # Verificar se há tabela de permissões
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_permissions'")
            permissions_table = cursor.fetchone()
            
            if permissions_table:
                print("✅ Tabela user_permissions existe!")
                
                # Verificar permissões do usuário
                cursor.execute("SELECT permission FROM user_permissions WHERE user_id = ?", (user[0],))
                permissions = cursor.fetchall()
                
                if permissions:
                    print(f"📋 Permissões encontradas: {len(permissions)}")
                    for perm in permissions:
                        print(f"   - {perm[0]}")
                else:
                    print("⚠️ Usuário não tem permissões específicas")
            else:
                print("❌ Tabela user_permissions NÃO existe!")
                
                # Verificar se há tabela de roles
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='roles'")
                roles_table = cursor.fetchone()
                
                if roles_table:
                    print("✅ Tabela roles existe!")
                    
                    # Verificar role do usuário
                    cursor.execute("SELECT permissions FROM roles WHERE name = ?", (user[3],))
                    role_permissions = cursor.fetchone()
                    
                    if role_permissions:
                        print(f"📋 Permissões do role '{user[3]}': {role_permissions[0]}")
                    else:
                        print(f"⚠️ Role '{user[3]}' não tem permissões definidas")
                else:
                    print("❌ Tabela roles NÃO existe!")
                    
        else:
            print("❌ Usuário admin não encontrado!")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erro ao verificar permissões: {e}")

def test_admin_groups_access(cookies):
    """Testa o acesso à página de admin de grupos"""
    print("\n🌐 Testando acesso à página de admin de grupos...")
    
    try:
        response = requests.get(f"{BASE_URL}/admin/groups", cookies=cookies)
        print(f"📡 Status da página: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Página de admin de grupos carregada!")
            
            # Verificar se há mensagens de erro
            if 'Erro ao carregar dados iniciais' in response.text:
                print("❌ Erro JavaScript encontrado na página!")
            else:
                print("✅ Nenhum erro JavaScript encontrado")
                
            # Verificar se há grupos sendo exibidos
            if 'groups-grid' in response.text:
                print("✅ Estrutura de grupos encontrada na página")
            else:
                print("⚠️ Estrutura de grupos não encontrada na página")
                
        elif response.status_code == 403:
            print("❌ Acesso negado (403) - Usuário não tem permissão")
        elif response.status_code == 302:
            print("❌ Redirecionamento (302) - Usuário não autenticado ou sem permissão")
        else:
            print(f"❌ Erro inesperado: {response.status_code}")
            print(f"   Resposta: {response.text}")
            
    except Exception as e:
        print(f"❌ Erro ao testar página: {e}")

def test_api_permissions(cookies):
    """Testa se o usuário tem permissão para acessar a API de grupos"""
    print("\n🔌 Testando permissões na API...")
    
    try:
        # Testar API de grupos (GET)
        response = requests.get(f"{BASE_URL}/api/admin/groups", cookies=cookies)
        print(f"📡 API GET /api/admin/groups: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("✅ API retornou grupos com sucesso")
            else:
                print(f"❌ API retornou erro: {data.get('message')}")
        elif response.status_code == 403:
            print("❌ Acesso negado (403) - Usuário não tem permissão 'manage_users'")
        else:
            print(f"❌ Erro inesperado: {response.status_code}")
            
        # Testar API de criação de grupo (POST)
        response = requests.post(f"{BASE_URL}/api/admin/groups", 
                               json={"name": "Teste", "description": "Teste"}, 
                               cookies=cookies)
        print(f"📡 API POST /api/admin/groups: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Usuário tem permissão para criar grupos")
        elif response.status_code == 403:
            print("❌ Usuário NÃO tem permissão para criar grupos")
        else:
            print(f"❌ Erro inesperado: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Erro ao testar API: {e}")

def main():
    """Função principal de teste"""
    print("🚀 Testando permissões do usuário admin...")
    print(f"🌐 Servidor: {BASE_URL}")
    print(f"🗄️ Banco: {DB_PATH}")
    
    # Verificar permissões no banco de dados
    check_user_permissions()
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar acesso à página
    test_admin_groups_access(cookies)
    
    # Testar permissões na API
    test_api_permissions(cookies)
    
    print("\n✨ Testes concluídos!")

if __name__ == "__main__":
    main()

