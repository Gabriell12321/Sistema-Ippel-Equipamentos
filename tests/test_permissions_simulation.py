#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Teste para simular o que acontece no navegador quando a página carrega
"""

import requests
import time

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

def test_page_load_sequence(cookies):
    """Testa a sequência de carregamento da página"""
    print("\n🔄 Testando sequência de carregamento da página...")
    
    try:
        # 1. Carregar a página inicial
        print("📄 1. Carregando página inicial...")
        response = requests.get(f"{BASE_URL}/admin/permissions", cookies=cookies)
        if response.status_code != 200:
            print(f"   ❌ Erro ao carregar página: {response.status_code}")
            return
        
        print("   ✅ Página carregada com sucesso")
        
        # 2. Simular chamada para carregar grupos (que deveria acontecer no loadInitialData)
        print("\n📋 2. Simulando carregamento de grupos...")
        groups_response = requests.get(f"{BASE_URL}/api/admin/groups", cookies=cookies)
        if groups_response.status_code == 200:
            groups_data = groups_response.json()
            if groups_data.get('success'):
                groups = groups_data.get('groups', [])
                print(f"   ✅ {len(groups)} grupos carregados via API")
                for group in groups[:3]:
                    print(f"      - {group['name']} (ID: {group['id']})")
            else:
                print(f"   ❌ Erro na API de grupos: {groups_data.get('message')}")
        else:
            print(f"   ❌ Erro na API de grupos: {groups_response.status_code}")
        
        # 3. Simular chamada para carregar permissões (que deveria acontecer no loadInitialData)
        print("\n🔐 3. Simulando carregamento de permissões...")
        permissions_response = requests.get(f"{BASE_URL}/api/admin/permissions/list", cookies=cookies)
        if permissions_response.status_code == 200:
            permissions_data = permissions_response.json()
            if permissions_data.get('success'):
                permissions = permissions_data.get('permissions', [])
                print(f"   ✅ {len(permissions)} permissões carregadas via API")
                for perm in permissions[:3]:
                    print(f"      - {perm['name']}: {perm['display_name']}")
            else:
                print(f"   ❌ Erro na API de permissões: {permissions_data.get('message')}")
        else:
            print(f"   ❌ Erro na API de permissões: {permissions_response.status_code}")
        
        # 4. Simular seleção de um grupo específico
        print("\n🎯 4. Simulando seleção de grupo...")
        if groups_response.status_code == 200 and groups_data.get('success'):
            groups = groups_data.get('groups', [])
            if groups:
                first_group = groups[0]
                group_id = first_group['id']
                print(f"   🎯 Selecionando grupo: {first_group['name']} (ID: {group_id})")
                
                # 5. Simular carregamento de permissões do grupo
                print(f"\n🔍 5. Simulando carregamento de permissões do grupo {group_id}...")
                group_permissions_response = requests.get(f"{BASE_URL}/api/admin/groups/{group_id}/permissions", cookies=cookies)
                if group_permissions_response.status_code == 200:
                    group_permissions_data = group_permissions_response.json()
                    if group_permissions_data.get('success'):
                        group_permissions = group_permissions_data.get('permissions', [])
                        print(f"   ✅ {len(group_permissions)} permissões carregadas para o grupo {group_id}")
                        for perm in group_permissions[:5]:
                            print(f"      - {perm}")
                    else:
                        print(f"   ❌ Erro ao carregar permissões do grupo: {group_permissions_data.get('error')}")
                else:
                    print(f"   ❌ Erro na API de permissões do grupo: {group_permissions_response.status_code}")
            else:
                print("   ⚠️ Nenhum grupo disponível para teste")
        else:
            print("   ⚠️ Não foi possível obter grupos para teste")
        
        print("\n✅ Sequência de carregamento simulada com sucesso!")
        
    except Exception as e:
        print(f"❌ Erro durante simulação: {e}")

def test_error_analysis(cookies):
    """Analisa possíveis causas do erro"""
    print("\n🔍 Analisando possíveis causas do erro...")
    
    try:
        # Verificar se há problemas de permissão
        print("🔐 Verificando permissões do usuário...")
        user_permissions_response = requests.get(f"{BASE_URL}/api/user/permissions", cookies=cookies)
        if user_permissions_response.status_code == 200:
            user_permissions_data = user_permissions_response.json()
            permissions = user_permissions_data.get('permissions', [])
            print(f"   ✅ Usuário tem {len(permissions)} permissões")
            if 'all' in permissions:
                print("   🎯 Usuário tem acesso total (admin)")
            else:
                print("   📋 Permissões específicas:", permissions[:5])
        else:
            print(f"   ❌ Erro ao verificar permissões do usuário: {user_permissions_response.status_code}")
        
        # Verificar se há problemas de sessão
        print("\n🆔 Verificando sessão...")
        session_response = requests.get(f"{BASE_URL}/admin/permissions", cookies=cookies, allow_redirects=False)
        if session_response.status_code == 302:
            print("   ❌ Usuário foi redirecionado (sessão expirada)")
        elif session_response.status_code == 200:
            print("   ✅ Sessão válida")
        else:
            print(f"   ⚠️ Status inesperado: {session_response.status_code}")
        
        # Verificar se há problemas de CORS ou headers
        print("\n📡 Verificando headers da resposta...")
        if session_response.status_code == 200:
            headers = session_response.headers
            print(f"   Content-Type: {headers.get('Content-Type', 'N/A')}")
            print(f"   Cache-Control: {headers.get('Cache-Control', 'N/A')}")
            print(f"   Content-Length: {headers.get('Content-Length', 'N/A')}")
        
    except Exception as e:
        print(f"❌ Erro durante análise: {e}")

def main():
    """Função principal de teste"""
    print("🚀 Testando simulação de carregamento da página...")
    print(f"🌐 Servidor: {BASE_URL}")
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar sequência de carregamento
    test_page_load_sequence(cookies)
    
    # Analisar possíveis causas do erro
    test_error_analysis(cookies)
    
    print("\n✨ Testes concluídos!")

if __name__ == "__main__":
    main()
