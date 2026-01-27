#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Teste para verificar a página de permissões e identificar o erro JavaScript
"""

import requests
from bs4 import BeautifulSoup

# Configurações
BASE_URL = "http://localhost:5001"
from tests.test_config import TEST_EMAIL, TEST_PASSWORD

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

def test_permissions_page(cookies):
    """Testa a página de permissões e analisa o HTML"""
    print("\n🌐 Testando página de admin de permissões...")
    
    try:
        response = requests.get(f"{BASE_URL}/admin/permissions", cookies=cookies)
        print(f"📡 Status da página: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Página de admin de permissões carregada!")
            
            # Analisar o HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Verificar se há erros no JavaScript
            if 'Erro ao carregar dados iniciais' in response.text:
                print("❌ Erro JavaScript encontrado na página!")
                
                # Procurar por mensagens de erro específicas
                error_patterns = [
                    'Erro ao carregar dados iniciais',
                    'Erro ao carregar permissões',
                    'SyntaxError',
                    'Unexpected token'
                ]
                
                for pattern in error_patterns:
                    if pattern in response.text:
                        print(f"   🔍 Padrão de erro encontrado: {pattern}")
                
            else:
                print("✅ Nenhum erro JavaScript encontrado")
            
            # Verificar elementos importantes
            print("\n🔍 Verificando elementos da página...")
            
            # Verificar seletor de grupos
            group_select = soup.find('select', {'id': 'groupSelect'})
            if group_select:
                print("✅ Seletor de grupos encontrado")
                options = group_select.find_all('option')
                print(f"   📋 {len(options)} opções encontradas")
                for option in options[:3]:  # Mostrar apenas as primeiras 3
                    print(f"      - {option.get_text()}")
            else:
                print("❌ Seletor de grupos NÃO encontrado")
            
            # Verificar container de permissões
            permissions_container = soup.find('div', {'id': 'permissionsContainer'})
            if permissions_container:
                print("✅ Container de permissões encontrado")
                content = permissions_container.get_text().strip()
                if content:
                    print(f"   📝 Conteúdo: {content[:100]}...")
                else:
                    print("   📝 Container vazio")
            else:
                print("❌ Container de permissões NÃO encontrado")
            
            # Verificar estatísticas do grupo
            group_stats = soup.find('div', {'id': 'groupStats'})
            if group_stats:
                print("✅ Estatísticas do grupo encontradas")
            else:
                print("❌ Estatísticas do grupo NÃO encontradas")
            
            # Verificar se há JavaScript na página
            scripts = soup.find_all('script')
            print(f"\n📜 Scripts encontrados: {len(scripts)}")
            
            # Verificar se há funções JavaScript importantes
            js_content = ' '.join([script.get_text() for script in scripts])
            
            important_functions = [
                'loadInitialData',
                'loadGroupPermissions',
                'displayGroupPermissions',
                'updateGroupStats',
                'showNotification'
            ]
            
            print("\n🔧 Verificando funções JavaScript...")
            for func in important_functions:
                if func in js_content:
                    print(f"   ✅ Função {func} encontrada")
                else:
                    print(f"   ❌ Função {func} NÃO encontrada")
            
            # Verificar se há variáveis JavaScript importantes
            important_vars = [
                'allGroups',
                'allPermissions',
                'currentGroupPermissions'
            ]
            
            print("\n📊 Verificando variáveis JavaScript...")
            for var in important_vars:
                if var in js_content:
                    print(f"   ✅ Variável {var} encontrada")
                else:
                    print(f"   ❌ Variável {var} NÃO encontrada")
                
        else:
            print(f"❌ Erro ao carregar página: {response.status_code}")
            print(f"   Resposta: {response.text}")
            
    except Exception as e:
        print(f"❌ Erro ao testar página: {e}")

def main():
    """Função principal de teste"""
    print("🚀 Testando página de permissões em detalhes...")
    print(f"🌐 Servidor: {BASE_URL}")
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar página de permissões
    test_permissions_page(cookies)
    
    print("\n✨ Testes concluídos!")

if __name__ == "__main__":
    main()
