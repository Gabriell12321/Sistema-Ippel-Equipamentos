#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Teste para debugar problemas com grupos
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

def test_database_groups():
    """Testa se a tabela groups existe e tem dados"""
    print("\n🗄️ Testando banco de dados...")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verificar se a tabela groups existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='groups'")
        table_exists = cursor.fetchone()
        
        if table_exists:
            print("✅ Tabela 'groups' existe!")
            
            # Verificar estrutura da tabela
            cursor.execute("PRAGMA table_info(groups)")
            columns = cursor.fetchall()
            print(f"📋 Colunas da tabela groups: {len(columns)}")
            for col in columns:
                print(f"   - {col[1]} ({col[2]})")
            
            # Verificar se há dados
            cursor.execute("SELECT COUNT(*) FROM groups")
            count = cursor.fetchone()[0]
            print(f"📊 Total de grupos: {count}")
            
            if count > 0:
                # Mostrar alguns grupos
                cursor.execute("SELECT id, name, description FROM groups LIMIT 5")
                groups = cursor.fetchall()
                print("📋 Grupos encontrados:")
                for group in groups:
                    print(f"   - ID: {group[0]}, Nome: {group[1]}, Descrição: {group[2]}")
            else:
                print("⚠️ Tabela groups está vazia!")
                
        else:
            print("❌ Tabela 'groups' NÃO existe!")
            
            # Verificar outras tabelas relacionadas
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            print(f"📋 Tabelas disponíveis: {len(tables)}")
            for table in tables:
                print(f"   - {table[0]}")
        
        conn.close()
        return table_exists is not None
        
    except Exception as e:
        print(f"❌ Erro ao acessar banco de dados: {e}")
        return False

def test_api_groups(cookies):
    """Testa a API de grupos"""
    print("\n🔌 Testando API de grupos...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/admin/groups", cookies=cookies)
        print(f"📡 Status da API: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                groups = data.get('groups', [])
                print(f"✅ API retornou {len(groups)} grupos")
                for group in groups[:3]:  # Mostrar apenas os primeiros 3
                    print(f"   - ID: {group['id']}, Nome: {group['name']}")
            else:
                print(f"❌ API retornou erro: {data.get('message')}")
        else:
            print(f"❌ Erro na API: {response.status_code}")
            print(f"   Resposta: {response.text}")
            
    except Exception as e:
        print(f"❌ Erro ao testar API: {e}")

def test_admin_groups_page(cookies):
    """Testa a página de admin de grupos"""
    print("\n🌐 Testando página de admin de grupos...")
    
    try:
        response = requests.get(f"{BASE_URL}/admin/groups", cookies=cookies)
        print(f"📡 Status da página: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Página de admin de grupos carregada!")
            
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

def create_sample_groups():
    """Cria grupos de exemplo se a tabela estiver vazia"""
    print("\n🔧 Criando grupos de exemplo...")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verificar se há grupos
        cursor.execute("SELECT COUNT(*) FROM groups")
        count = cursor.fetchone()[0]
        
        if count == 0:
            print("📝 Criando grupos de exemplo...")
            
            sample_groups = [
                ("Administradores", "Grupo com acesso total ao sistema"),
                ("Usuários", "Usuários padrão do sistema"),
                ("Gerentes", "Gerentes de departamento"),
                ("Operadores", "Operadores de linha")
            ]
            
            for name, description in sample_groups:
                cursor.execute("INSERT INTO groups (name, description) VALUES (?, ?)", (name, description))
                print(f"   ✅ Criado grupo: {name}")
            
            conn.commit()
            print(f"✅ {len(sample_groups)} grupos criados com sucesso!")
        else:
            print(f"✅ Já existem {count} grupos no sistema")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erro ao criar grupos: {e}")

def main():
    """Função principal de teste"""
    print("🚀 Testando sistema de grupos...")
    print(f"🌐 Servidor: {BASE_URL}")
    print(f"🗄️ Banco: {DB_PATH}")
    
    # Testar banco de dados
    db_ok = test_database_groups()
    
    # Se a tabela não existir ou estiver vazia, criar grupos de exemplo
    if not db_ok:
        print("\n⚠️ Problema detectado no banco de dados!")
        return
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar API de grupos
    test_api_groups(cookies)
    
    # Testar página de admin
    test_admin_groups_page(cookies)
    
    print("\n✨ Testes concluídos!")

if __name__ == "__main__":
    main()

