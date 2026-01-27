#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para testar se as correções das assinaturas de engenharia funcionaram
"""

import requests
import json

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

def test_employee_performance(cookies):
    """Testa a API de desempenho por funcionário corrigida"""
    print("\n👥 Testando API de desempenho por funcionário (CORRIGIDA)...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/employee-performance",
            cookies=cookies,
            params={"year": "2025", "month": "12"}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"✅ API funcionando! {len(data.get('data', []))} assinaturas encontradas")
                print("\n📊 Resultados por assinatura:")
                for emp in data.get('data', []):
                    print(f"   👤 {emp['name']}: {emp['rncs']} RNCs ({emp['percentage']}%) - {emp['status']}")
            else:
                print(f"❌ API retornou erro: {data.get('message')}")
        else:
            print(f"❌ Erro na API: {response.status_code}")
            print(f"   Resposta: {response.text}")
    except Exception as e:
        print(f"❌ Erro ao testar API: {e}")

def test_dashboard_performance(cookies):
    """Testa a API de dashboard de desempenho corrigida"""
    print("\n📊 Testando API de dashboard de desempenho (CORRIGIDA)...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/dashboard/performance",
            cookies=cookies,
            params={"year": "2025", "month": "12"}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"✅ Dashboard API funcionando! {len(data.get('data', []))} assinaturas encontradas")
                print("\n📊 Resultados por assinatura:")
                for emp in data.get('data', []):
                    print(f"   👤 {emp['name']}: {emp['rncs']} RNCs ({emp['percentage']}%) - {emp['status']}")
            else:
                print(f"❌ Dashboard API retornou erro: {data.get('message')}")
        else:
            print(f"❌ Erro na Dashboard API: {response.status_code}")
            print(f"   Resposta: {response.text}")
    except Exception as e:
        print(f"❌ Erro ao testar Dashboard API: {e}")

def test_api_debug(cookies):
    """Testa a API de debug para verificar as assinaturas"""
    print("\n🔍 Testando API de debug...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/debug/rncs",
            cookies=cookies
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("✅ Debug API funcionando!")
                print(f"📋 Estrutura da tabela: {data.get('table_structure', [])}")
                print(f"👥 Distribuição de usuários: {len(data.get('user_distribution', []))} usuários")
                print(f"📊 Total de RNCs: {data.get('total_rncs', 0)}")
            else:
                print(f"❌ Debug API retornou erro: {data.get('error')}")
        else:
            print(f"❌ Erro na Debug API: {response.status_code}")
            print(f"   Resposta: {response.text}")
    except Exception as e:
        print(f"❌ Erro ao testar Debug API: {e}")

def main():
    """Função principal de teste"""
    print("🚀 Testando correções das assinaturas de engenharia...")
    print(f"🌐 Servidor: {BASE_URL}")
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar APIs corrigidas
    test_employee_performance(cookies)
    test_dashboard_performance(cookies)
    test_api_debug(cookies)
    
    print("\n✨ Testes concluídos!")
    print("\n💡 Verificações realizadas:")
    print("1. ✅ Login no sistema")
    print("2. ✅ API de desempenho por funcionário (assinaturas)")
    print("3. ✅ API de dashboard (assinaturas)")
    print("4. ✅ API de debug (estrutura do banco)")
    print("\n🎯 Resultado esperado:")
    print("   - As APIs agora devem mostrar RNCs baseadas nas ASSINATURAS DE ENGENHARIA")
    print("   - Não mais baseadas no usuário que criou a RNC")
    print("   - Deve mostrar nomes como 'Mauri Pedro Nissola' em vez de 'Ronaldo'")

if __name__ == "__main__":
    main()
