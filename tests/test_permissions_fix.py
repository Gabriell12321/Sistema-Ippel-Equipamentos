#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Teste para verificar se as APIs de permissões estão funcionando
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

def check_database_tables():
    """Verifica se as tabelas necessárias existem no banco de dados"""
    print("\n🗄️ Verificando tabelas do banco de dados...")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verificar tabela groups
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='groups'")
        groups_table = cursor.fetchone()
        if groups_table:
            print("✅ Tabela 'groups' existe!")
            
            # Verificar se há grupos
            cursor.execute("SELECT COUNT(*) FROM groups")
            groups_count = cursor.fetchone()[0]
            print(f"📊 Total de grupos: {groups_count}")
            
            if groups_count > 0:
                cursor.execute("SELECT id, name FROM groups LIMIT 3")
                groups = cursor.fetchall()
                print("📋 Grupos encontrados:")
                for group in groups:
                    print(f"   - ID: {group[0]}, Nome: {group[1]}")
        else:
            print("❌ Tabela 'groups' NÃO existe!")
        
        # Verificar tabela group_permissions
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='group_permissions'")
        permissions_table = cursor.fetchone()
        if permissions_table:
            print("✅ Tabela 'group_permissions' existe!")
            
            # Verificar estrutura
            cursor.execute("PRAGMA table_info(group_permissions)")
            columns = cursor.fetchall()
            print(f"📋 Colunas da tabela group_permissions: {len(columns)}")
            for col in columns:
                print(f"   - {col[1]} ({col[2]})")
        else:
            print("❌ Tabela 'group_permissions' NÃO existe!")
            
            # Criar a tabela se não existir
            print("🔧 Criando tabela group_permissions...")
            cursor.execute('''CREATE TABLE IF NOT EXISTS group_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                permission_name TEXT NOT NULL,
                permission_value INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
                UNIQUE(group_id, permission_name)
            )''')
            conn.commit()
            print("✅ Tabela 'group_permissions' criada com sucesso!")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erro ao verificar banco de dados: {e}")

def test_permissions_apis(cookies):
    """Testa as APIs de permissões"""
    print("\n🔌 Testando APIs de permissões...")
    
    try:
        # Testar API de lista de permissões
        print("📡 Testando /api/admin/permissions/list...")
        response = requests.get(f"{BASE_URL}/api/admin/permissions/list", cookies=cookies)
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                permissions = data.get('permissions', [])
                print(f"   ✅ API retornou {len(permissions)} permissões")
                for perm in permissions[:3]:  # Mostrar apenas as primeiras 3
                    print(f"      - {perm['name']}: {perm['display_name']}")
            else:
                print(f"   ❌ API retornou erro: {data.get('error')}")
        else:
            print(f"   ❌ Erro na API: {response.status_code}")
            print(f"      Resposta: {response.text}")
        
        # Testar API de permissões de um grupo específico
        print("\n📡 Testando /api/admin/groups/1/permissions...")
        response = requests.get(f"{BASE_URL}/api/admin/groups/1/permissions", cookies=cookies)
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                permissions = data.get('permissions', [])
                print(f"   ✅ API retornou {len(permissions)} permissões para o grupo 1")
                for perm in permissions:
                    print(f"      - {perm}")
            else:
                print(f"   ❌ API retornou erro: {data.get('error')}")
        elif response.status_code == 404:
            print("   ❌ API retornou 404 - Grupo não encontrado ou API não implementada")
        else:
            print(f"   ❌ Erro na API: {response.status_code}")
            print(f"      Resposta: {response.text}")
            
    except Exception as e:
        print(f"❌ Erro ao testar APIs: {e}")

def test_admin_permissions_page(cookies):
    """Testa a página de admin de permissões"""
    print("\n🌐 Testando página de admin de permissões...")
    
    try:
        response = requests.get(f"{BASE_URL}/admin/permissions", cookies=cookies)
        print(f"📡 Status da página: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Página de admin de permissões carregada!")
            
            # Verificar se há erros no JavaScript
            if 'Erro ao carregar dados iniciais' in response.text:
                print("❌ Erro JavaScript encontrado na página!")
            else:
                print("✅ Nenhum erro JavaScript encontrado")
                
        else:
            print(f"❌ Erro ao carregar página: {response.status_code}")
            print(f"   Resposta: {response.text}")
            
    except Exception as e:
        print(f"❌ Erro ao testar página: {e}")

def main():
    """Função principal de teste"""
    print("🚀 Testando sistema de permissões...")
    print(f"🌐 Servidor: {BASE_URL}")
    print(f"🗄️ Banco: {DB_PATH}")
    
    # Verificar banco de dados
    check_database_tables()
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar APIs de permissões
    test_permissions_apis(cookies)
    
    # Testar página de admin
    test_admin_permissions_page(cookies)
    
    print("\n✨ Testes concluídos!")

if __name__ == "__main__":
    main()
