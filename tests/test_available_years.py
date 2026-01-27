#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para testar a nova API de anos disponíveis
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

def test_available_years(cookies):
    """Testa a nova API de anos disponíveis"""
    print("\n📅 Testando API de anos disponíveis...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/available-years",
            cookies=cookies
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                years = data.get('years', [])
                current_year = data.get('current_year', 'N/A')
                print(f"✅ API funcionando!")
                print(f"📅 Ano atual: {current_year}")
                print(f"📅 Anos disponíveis: {years}")
                print(f"📊 Total de anos: {len(years)}")
                
                # Verificar se inclui anos futuros
                future_years = [y for y in years if int(y) > int(current_year)]
                if future_years:
                    print(f"🔮 Anos futuros incluídos: {future_years}")
                else:
                    print("⚠️ Nenhum ano futuro incluído")
                
                return years
            else:
                print(f"❌ API retornou erro: {data.get('message')}")
                return None
        else:
            print(f"❌ Erro na API: {response.status_code}")
            print(f"   Resposta: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Erro ao testar API: {e}")
        return None

def test_employee_performance_with_years(cookies, years):
    """Testa a API de desempenho com diferentes anos"""
    print("\n👥 Testando API de desempenho com diferentes anos...")
    
    for year in years[:5]:  # Testar apenas os primeiros 5 anos
        try:
            response = requests.get(
                f"{BASE_URL}/api/employee-performance",
                cookies=cookies,
                params={"year": year}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    count = len(data.get('data', []))
                    print(f"✅ Ano {year}: {count} funcionários encontrados")
                else:
                    print(f"❌ Ano {year}: {data.get('message')}")
            else:
                print(f"❌ Ano {year}: Erro {response.status_code}")
                
        except Exception as e:
            print(f"❌ Ano {year}: Erro {e}")

def main():
    """Função principal de teste"""
    print("🚀 Testando nova API de anos disponíveis...")
    print(f"🌐 Servidor: {BASE_URL}")
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar API de anos disponíveis
    years = test_available_years(cookies)
    if not years:
        print("❌ Não foi possível obter os anos disponíveis.")
        return
    
    # Testar API de desempenho com diferentes anos
    test_employee_performance_with_years(cookies, years)
    
    print("\n✨ Testes concluídos!")
    print("\n💡 Verificações realizadas:")
    print("1. ✅ Login no sistema")
    print("2. ✅ API de anos disponíveis")
    print("3. ✅ API de desempenho com diferentes anos")
    print("\n🎯 Resultado esperado:")
    print("   - A API deve retornar todos os anos disponíveis no banco")
    print("   - Deve incluir o ano atual e anos futuros")
    print("   - O seletor de anos no frontend deve ser atualizado dinamicamente")

if __name__ == "__main__":
    main()
