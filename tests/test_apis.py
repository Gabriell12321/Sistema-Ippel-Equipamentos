#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Teste das APIs corrigidas do servidor
"""

import requests
import json

# Configurações
BASE_URL = "http://localhost:5000"
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
    """Testa a API de desempenho por funcionário"""
    print("\n👥 Testando API de desempenho por funcionário...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/employee-performance",
            cookies=cookies,
            params={"year": "2023", "month": "Maio"}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"✅ API funcionando! {len(data.get('data', []))} funcionários encontrados")
                for emp in data.get('data', [])[:3]:
                    print(f"   👤 {emp['name']}: {emp['rncs']} RNCs ({emp['percentage']}%)")
            else:
                print(f"❌ API retornou erro: {data.get('message')}")
        else:
            print(f"❌ Erro na API: {response.status_code}")
            print(f"   Resposta: {response.text}")
    except Exception as e:
        print(f"❌ Erro ao testar API: {e}")

def test_dashboard_performance(cookies):
    """Testa a nova API de dashboard de desempenho"""
    print("\n📊 Testando API de dashboard de desempenho...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/dashboard/performance",
            cookies=cookies,
            params={"year": "2023", "month": "Maio"}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"✅ Dashboard API funcionando! {len(data.get('data', []))} funcionários encontrados")
                for emp in data.get('data', [])[:3]:
                    print(f"   👤 {emp['name']}: {emp['rncs']} RNCs ({emp['percentage']}%)")
            else:
                print(f"❌ Dashboard API retornou erro: {data.get('message')}")
        else:
            print(f"❌ Erro na Dashboard API: {response.status_code}")
            print(f"   Resposta: {response.text}")
    except Exception as e:
        print(f"❌ Erro ao testar Dashboard API: {e}")

def test_dashboard_charts(cookies):
    """Testa a nova API de gráficos do dashboard"""
    print("\n📈 Testando API de gráficos do dashboard...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/dashboard/charts",
            cookies=cookies,
            params={"period": "30"}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("✅ Dashboard Charts API funcionando!")
                print(f"   📊 Status: {len(data.get('status', []))} categorias")
                print(f"   🏢 Departamentos: {len(data.get('departments', []))} departamentos")
                print(f"   👥 Usuários: {len(data.get('users', []))} usuários")
                print(f"   📅 Tendência: {len(data.get('trend', []))} datas")
            else:
                print(f"❌ Dashboard Charts API retornou erro: {data.get('error')}")
        else:
            print(f"❌ Erro na Dashboard Charts API: {response.status_code}")
            print(f"   Resposta: {response.text}")
    except Exception as e:
        print(f"❌ Erro ao testar Dashboard Charts API: {e}")

def test_charts_data(cookies):
    """Testa a API de gráficos original"""
    print("\n📊 Testando API de gráficos original...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/charts/data",
            cookies=cookies,
            params={"period": "30"}
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Charts Data API funcionando!")
            print(f"   📊 Status: {len(data.get('status', []))} categorias")
            print(f"   🏢 Departamentos: {len(data.get('departments', []))} departamentos")
            print(f"   👥 Usuários: {len(data.get('users', []))} usuários")
        else:
            print(f"❌ Erro na Charts Data API: {response.status_code}")
            print(f"   Resposta: {response.text}")
    except Exception as e:
        print(f"❌ Erro ao testar Charts Data API: {e}")

def main():
    """Função principal de teste"""
    print("🚀 Iniciando testes das APIs corrigidas...")
    print(f"🌐 Servidor: {BASE_URL}")
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar APIs
    test_employee_performance(cookies)
    test_dashboard_performance(cookies)
    test_dashboard_charts(cookies)
    test_charts_data(cookies)
    
    print("\n✨ Testes concluídos!")

if __name__ == "__main__":
    main()
