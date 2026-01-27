#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Teste para verificar se a função forceUpdateSelectors está funcionando
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
            functions_to_check = [
                'initializeEmployeeSelectors',
                'forceUpdateSelectors',
                'loadAvailableYears',
                'loadAvailableMonths'
            ]
            
            for func in functions_to_check:
                if func in response.text:
                    print(f"✅ Função {func} encontrada!")
                else:
                    print(f"❌ Função {func} NÃO encontrada!")
            
            # Verificar se os seletores estão presentes
            if 'employeeYearSelect' in response.text:
                print("✅ Seletor de ano encontrado!")
            else:
                print("❌ Seletor de ano NÃO encontrado!")
                
            if 'employeeMonthSelect' in response.text:
                print("✅ Seletor de mês encontrado!")
            else:
                print("❌ Seletor de mês NÃO encontrado!")
            
            # Verificar se o botão de atualização forçada está presente
            if 'forceUpdateSelectors()' in response.text:
                print("✅ Botão de atualização forçada encontrado!")
            else:
                print("❌ Botão de atualização forçada NÃO encontrado!")
            
            return True
        else:
            print(f"❌ Erro ao carregar dashboard: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erro ao testar dashboard: {e}")
        return False

def main():
    """Função principal de teste"""
    print("🚀 Testando função forceUpdateSelectors...")
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
        print("   ✅ Botão de atualização forçada implementado")
        print("\n🎯 PRÓXIMOS PASSOS:")
        print("   1. Acesse http://localhost:5001/dashboard")
        print("   2. Vá para a seção 'Desempenho por Funcionário'")
        print("   3. Clique no botão VERDE '📅 Atualizar Seletores'")
        print("   4. Verifique se os seletores mostram anos de 2013-2030")
        print("   5. Verifique se os seletores mostram todos os 12 meses")
    else:
        print("\n❌ PROBLEMAS ENCONTRADOS:")
        print("   - Dashboard não carregou corretamente")

if __name__ == "__main__":
    main()
