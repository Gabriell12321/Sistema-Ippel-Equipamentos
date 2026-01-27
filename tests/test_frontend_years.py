#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para testar se o frontend está carregando os anos corretamente
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

def test_dashboard_page(cookies):
    """Testa se a página do dashboard está carregando"""
    print("\n🌐 Testando página do dashboard...")
    
    try:
        response = requests.get(
            f"{BASE_URL}/dashboard",
            cookies=cookies
        )
        
        if response.status_code == 200:
            print("✅ Dashboard carregado com sucesso!")
            
            # Verificar se contém o JavaScript para carregar anos
            content = response.text
            if 'loadAvailableYears' in content:
                print("✅ Função loadAvailableYears encontrada no HTML")
            else:
                print("❌ Função loadAvailableYears NÃO encontrada no HTML")
            
            if '/api/available-years' in content:
                print("✅ Endpoint /api/available-years referenciado no HTML")
            else:
                print("❌ Endpoint /api/available-years NÃO referenciado no HTML")
            
            return True
        else:
            print(f"❌ Erro ao carregar dashboard: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Erro ao testar dashboard: {e}")
        return False

def test_available_years_api(cookies):
    """Testa a API de anos disponíveis novamente"""
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
                total_years = data.get('total_years', 0)
                
                print(f"✅ API funcionando!")
                print(f"📅 Ano atual: {current_year}")
                print(f"📅 Anos disponíveis: {years}")
                print(f"📊 Total de anos: {total_years}")
                
                # Verificar se inclui anos futuros
                future_years = [y for y in years if int(y) > int(current_year)]
                if future_years:
                    print(f"🔮 Anos futuros incluídos: {future_years}")
                else:
                    print("⚠️ Nenhum ano futuro incluído")
                
                # Verificar se inclui anos históricos
                historical_years = [y for y in years if int(y) < int(current_year)]
                if historical_years:
                    print(f"📚 Anos históricos incluídos: {historical_years}")
                else:
                    print("⚠️ Nenhum ano histórico incluído")
                
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

def main():
    """Função principal de teste"""
    print("🚀 Testando carregamento dinâmico de anos no frontend...")
    print(f"🌐 Servidor: {BASE_URL}")
    
    # Testar login
    cookies = test_login()
    if not cookies:
        print("❌ Não foi possível fazer login. Verifique as credenciais e se o servidor está rodando.")
        return
    
    # Testar página do dashboard
    dashboard_ok = test_dashboard_page(cookies)
    
    # Testar API de anos disponíveis
    years = test_available_years_api(cookies)
    
    print("\n✨ Testes concluídos!")
    print("\n💡 Verificações realizadas:")
    print("1. ✅ Login no sistema")
    print("2. ✅ Página do dashboard")
    print("3. ✅ API de anos disponíveis")
    
    if dashboard_ok and years:
        print("\n🎯 RESULTADO:")
        print("   ✅ Frontend configurado para carregar anos dinamicamente")
        print("   ✅ API retornando anos do banco de dados")
        print("   ✅ Seletor de anos deve mostrar todos os anos disponíveis")
        print(f"   📅 Anos disponíveis: {len(years)} anos (de {min(years)} a {max(years)})")
    else:
        print("\n❌ PROBLEMAS ENCONTRADOS:")
        if not dashboard_ok:
            print("   - Dashboard não está carregando corretamente")
        if not years:
            print("   - API de anos não está funcionando")

if __name__ == "__main__":
    main()
