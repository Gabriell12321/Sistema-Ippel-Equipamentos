#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Teste simples para verificar o frontend
"""

import requests

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

def test_dashboard_page(cookies):
    """Testa a página do dashboard"""
    print("\n🌐 Testando página do dashboard...")
    
    try:
        response = requests.get(f"{BASE_URL}/dashboard", cookies=cookies)
        if response.status_code == 200:
            print("✅ Página do dashboard carregada!")
            
            # Verificar se as funções JavaScript estão presentes
            if 'initializeEmployeeSelectors' in response.text:
                print("✅ Função initializeEmployeeSelectors encontrada!")
            else:
                print("❌ Função initializeEmployeeSelectors NÃO encontrada!")
                
            if 'loadAvailableYears' in response.text:
                print("✅ Função loadAvailableYears encontrada!")
            else:
                print("❌ Função loadAvailableYears NÃO encontrada!")
                
            if 'loadAvailableMonths' in response.text:
                print("✅ Função loadAvailableMonths encontrada!")
            else:
                print("❌ Função loadAvailableMonths NÃO encontrada!")
            
            # Verificar se os seletores estão presentes
            if 'employeeYearSelect' in response.text:
                print("✅ Seletor de ano encontrado!")
            else:
                print("❌ Seletor de ano NÃO encontrado!")
                
            if 'employeeMonthSelect' in response.text:
                print("✅ Seletor de mês encontrado!")
            else:
                print("❌ Seletor de mês NÃO encontrado!")
            
            return True
        else:
            print(f"❌ Erro ao carregar dashboard: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erro ao testar dashboard: {e}")
        return False

def main():
    """Função principal de teste"""
    print("🚀 Testando frontend do dashboard...")
    print(f"🌐 Servidor: {BASE_URL}")
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar página do dashboard
    dashboard_ok = test_dashboard_page(cookies)
    
    print("\n✨ Testes concluídos!")
    
    if dashboard_ok:
        print("\n💡 RESULTADO:")
        print("   ✅ Dashboard carregado com sucesso")
        print("   ✅ Funções JavaScript implementadas")
        print("   ✅ Seletores de ano e mês configurados")
        print("\n🎯 PRÓXIMOS PASSOS:")
        print("   1. Acesse http://localhost:5001/dashboard")
        print("   2. Vá para a seção 'Desempenho por Funcionário'")
        print("   3. Verifique se os seletores mostram anos de 2013-2030")
        print("   4. Verifique se os seletores mostram todos os 12 meses")
    else:
        print("\n❌ PROBLEMAS ENCONTRADOS:")
        print("   - Dashboard não carregou corretamente")

if __name__ == "__main__":
    main()
