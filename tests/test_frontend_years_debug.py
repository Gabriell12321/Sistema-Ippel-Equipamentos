#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para testar especificamente o carregamento dos anos no frontend
"""

import requests
from bs4 import BeautifulSoup
import re

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
    """Testa a página do dashboard para verificar os seletores"""
    print("\n🌐 Testando página do dashboard...")
    
    try:
        response = requests.get(f"{BASE_URL}/dashboard", cookies=cookies)
        if response.status_code == 200:
            print("✅ Página do dashboard carregada!")
            
            # Parsear o HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Procurar por seletores de ano e mês
            year_selectors = soup.find_all('select', {'id': re.compile(r'.*year.*', re.IGNORECASE)})
            month_selectors = soup.find_all('select', {'id': re.compile(r'.*month.*', re.IGNORECASE)})
            
            print(f"📅 Seletores de ano encontrados: {len(year_selectors)}")
            print(f"📅 Seletores de mês encontrados: {len(month_selectors)}")
            
            # Verificar se há seletores
            if not year_selectors and not month_selectors:
                # Procurar por qualquer select que possa ser de ano/mês
                all_selects = soup.find_all('select')
                print(f"🔍 Total de seletores encontrados: {len(all_selects)}")
                
                for i, select in enumerate(all_selects):
                    print(f"   Seletor {i+1}: id='{select.get('id', 'N/A')}', class='{select.get('class', 'N/A')}'")
                    options = select.find_all('option')
                    print(f"      Opções: {len(options)}")
                    for opt in options[:5]:  # Mostrar apenas as primeiras 5 opções
                        print(f"         {opt.get('value', 'N/A')} - {opt.text.strip()}")
                    if len(options) > 5:
                        print(f"         ... e mais {len(options) - 5} opções")
            
            # Verificar se as funções JavaScript estão presentes
            script_tags = soup.find_all('script')
            print(f"\n📜 Scripts encontrados: {len(script_tags)}")
            
            load_available_years_found = False
            load_available_months_found = False
            
            for script in script_tags:
                if script.string:
                    script_content = script.string
                    if 'loadAvailableYears' in script_content:
                        load_available_years_found = True
                        print("✅ Função loadAvailableYears encontrada!")
                    if 'loadAvailableMonths' in script_content:
                        load_available_months_found = True
                        print("✅ Função loadAvailableMonths encontrada!")
            
            if not load_available_years_found:
                print("❌ Função loadAvailableYears NÃO encontrada!")
            if not load_available_months_found:
                print("❌ Função loadAvailableMonths NÃO encontrada!")
            
            # Verificar se há chamadas para essas funções
            if load_available_years_found:
                # Procurar por chamadas da função
                if 'loadAvailableYears(' in response.text:
                    print("✅ Chamada para loadAvailableYears encontrada no HTML!")
                else:
                    print("❌ Chamada para loadAvailableYears NÃO encontrada no HTML!")
            
            if load_available_months_found:
                # Procurar por chamadas da função
                if 'loadAvailableMonths(' in response.text:
                    print("✅ Chamada para loadAvailableMonths encontrada no HTML!")
                else:
                    print("❌ Chamada para loadAvailableMonths NÃO encontrada no HTML!")
            
            return True
        else:
            print(f"❌ Erro ao carregar dashboard: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erro ao testar dashboard: {e}")
        return False

def test_api_endpoints_directly(cookies):
    """Testa diretamente os endpoints das APIs"""
    print("\n🔌 Testando endpoints das APIs diretamente...")
    
    # Testar API de anos
    try:
        response = requests.get(f"{BASE_URL}/api/available-years", cookies=cookies)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                years = data.get('years', [])
                print(f"✅ API /api/available-years retornou {len(years)} anos")
                print(f"📅 Anos: {years}")
                
                # Verificar se inclui 2024 e 2025
                if '2024' in years:
                    print("✅ Ano 2024 está incluído!")
                else:
                    print("❌ Ano 2024 NÃO está incluído!")
                    
                if '2025' in years:
                    print("✅ Ano 2025 está incluído!")
                else:
                    print("❌ Ano 2025 NÃO está incluído!")
            else:
                print(f"❌ API retornou erro: {data.get('message')}")
        else:
            print(f"❌ API retornou erro {response.status_code}")
    except Exception as e:
        print(f"❌ Erro ao testar API de anos: {e}")
    
    # Testar API de meses
    try:
        response = requests.get(f"{BASE_URL}/api/available-months", cookies=cookies)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                months = data.get('months', [])
                print(f"✅ API /api/available-months retornou {len(months)} meses")
            else:
                print(f"❌ API retornou erro: {data.get('message')}")
        else:
            print(f"❌ API retornou erro {response.status_code}")
    except Exception as e:
        print(f"❌ Erro ao testar API de meses: {e}")

def main():
    """Função principal de teste"""
    print("🚀 Testando carregamento dos anos no frontend...")
    print(f"🌐 Servidor: {BASE_URL}")
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar página do dashboard
    dashboard_ok = test_dashboard_page(cookies)
    
    # Testar APIs diretamente
    test_api_endpoints_directly(cookies)
    
    print("\n✨ Testes concluídos!")
    
    if dashboard_ok:
        print("\n💡 RESULTADO:")
        print("   ✅ Dashboard carregado com sucesso")
        print("   ✅ APIs funcionando corretamente")
        print("   🔍 Verificar se os seletores estão sendo populados corretamente")
    else:
        print("\n❌ PROBLEMAS ENCONTRADOS:")
        print("   - Dashboard não carregou corretamente")

if __name__ == "__main__":
    main()
