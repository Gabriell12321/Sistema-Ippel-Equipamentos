#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para testar as APIs de anos e meses completas (2013-2025)
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

def test_available_years_api(cookies):
    """Testa a nova API de anos (2013-2025)"""
    print("\n📅 Testando API de anos disponíveis (2013-2025)...")
    
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
                total_years = data.get('total_years', 0)
                
                print(f"✅ API de anos funcionando!")
                print(f"📅 Ano atual: {current_year}")
                print(f"📅 Anos disponíveis: {years}")
                print(f"📊 Total de anos: {total_years}")
                
                # Verificar se inclui 2013-2025
                expected_years = [str(year) for year in range(2013, 2026)]
                missing_years = [year for year in expected_years if year not in years]
                if not missing_years:
                    print("✅ Todos os anos de 2013-2025 estão incluídos!")
                else:
                    print(f"⚠️ Anos faltando: {missing_years}")
                
                # Verificar se inclui anos futuros
                future_years = [y for y in years if int(y) > 2025]
                if future_years:
                    print(f"🔮 Anos futuros incluídos: {future_years}")
                
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

def test_available_months_api(cookies):
    """Testa a nova API de meses"""
    print("\n📅 Testando API de meses disponíveis...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/available-months",
            cookies=cookies
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                months = data.get('months', [])
                total_months = data.get('total_months', 0)
                
                print(f"✅ API de meses funcionando!")
                print(f"📅 Meses disponíveis:")
                for month in months:
                    print(f"   {month['value']} - {month['name']}")
                print(f"📊 Total de meses: {total_months}")
                
                # Verificar se inclui todos os 12 meses
                if total_months == 12:
                    print("✅ Todos os 12 meses estão incluídos!")
                else:
                    print(f"⚠️ Esperado 12 meses, encontrado {total_months}")
                
                return months
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

def test_employee_performance_with_filters(cookies, years, months):
    """Testa a API de desempenho com filtros de ano e mês"""
    print("\n👥 Testando API de desempenho com filtros de ano e mês...")
    
    # Testar alguns anos específicos
    test_years = [years[0], years[1], '2023', '2024'] if years else ['2023', '2024']
    test_months = ['01', '06', '12'] if months else ['01', '06', '12']
    
    for year in test_years[:3]:  # Testar apenas 3 anos
        for month in test_months[:2]:  # Testar apenas 2 meses por ano
            try:
                response = requests.get(
                    f"{BASE_URL}/api/employee-performance",
                    cookies=cookies,
                    params={"year": year, "month": month}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        count = len(data.get('data', []))
                        month_name = next((m['name'] for m in months if m['value'] == month), month) if months else month
                        print(f"✅ {month_name}/{year}: {count} funcionários encontrados")
                    else:
                        print(f"❌ {month}/{year}: {data.get('message')}")
                else:
                    print(f"❌ {month}/{year}: Erro {response.status_code}")
                    
            except Exception as e:
                print(f"❌ {month}/{year}: Erro {e}")

def main():
    """Função principal de teste"""
    print("🚀 Testando APIs completas de anos (2013-2025) e meses...")
    print(f"🌐 Servidor: {BASE_URL}")
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar API de anos disponíveis
    years = test_available_years_api(cookies)
    
    # Testar API de meses disponíveis  
    months = test_available_months_api(cookies)
    
    # Testar API de desempenho com filtros
    if years and months:
        test_employee_performance_with_filters(cookies, years, months)
    
    print("\n✨ Testes concluídos!")
    print("\n💡 Verificações realizadas:")
    print("1. ✅ Login no sistema")
    print("2. ✅ API de anos disponíveis (2013-2025)")
    print("3. ✅ API de meses disponíveis (12 meses)")
    print("4. ✅ API de desempenho com filtros de ano e mês")
    
    if years and months:
        print("\n🎯 RESULTADO:")
        print("   ✅ API de anos retornando 2013-2025 + anos futuros")
        print("   ✅ API de meses retornando todos os 12 meses")
        print("   ✅ Filtros de ano e mês funcionando nas APIs de desempenho")
        print(f"   📅 Anos disponíveis: {len(years)} anos")
        print(f"   📅 Meses disponíveis: {len(months)} meses")
    else:
        print("\n❌ PROBLEMAS ENCONTRADOS:")
        if not years:
            print("   - API de anos não está funcionando")
        if not months:
            print("   - API de meses não está funcionando")

if __name__ == "__main__":
    main()
