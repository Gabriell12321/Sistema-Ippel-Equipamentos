#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para testar a API diretamente e verificar se há algum filtro ou limitação
"""

import requests
import json

# Configurações
BASE_URL = "http://localhost:5001"
from tests.test_config import TEST_EMAIL, TEST_PASSWORD

def test_api_direct():
    """Testar a API diretamente"""
    print("🔍 Testando API diretamente...")
    
    # 1. Login
    print("🔐 Fazendo login...")
    login_data = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/login", json=login_data)
        if response.status_code != 200:
            print(f"❌ Login falhou: {response.status_code}")
            return None
        
        data = response.json()
        if not data.get('success'):
            print(f"❌ Login falhou: {data.get('message')}")
            return None
        
        print("✅ Login realizado com sucesso!")
        cookies = response.cookies
        return cookies
        
    except Exception as e:
        print(f"❌ Erro no login: {e}")
        return None

def test_employee_performance_direct(cookies):
    """Testar API de desempenho diretamente"""
    print("\n👥 Testando API de desempenho diretamente...")
    
    try:
        # Testar sem filtros
        response = requests.get(
            f"{BASE_URL}/api/employee-performance",
            cookies=cookies
        )
        
        print(f"📊 Status: {response.status_code}")
        print(f"📊 Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"📊 Success: {data.get('success')}")
            print(f"📊 Data length: {len(data.get('data', []))}")
            print(f"📊 Filters: {data.get('filters', {})}")
            
            # Mostrar algumas assinaturas
            print(f"\n📝 Primeiras 10 assinaturas:")
            for i, emp in enumerate(data.get('data', [])[:10]):
                print(f"   {i+1:2d}. {emp['name']}: {emp['rncs']} RNCs")
        else:
            print(f"❌ Erro: {response.text}")
            
    except Exception as e:
        print(f"❌ Erro ao testar API: {e}")

def test_dashboard_performance_direct(cookies):
    """Testar API de dashboard diretamente"""
    print("\n📊 Testando API de dashboard diretamente...")
    
    try:
        # Testar sem filtros
        response = requests.get(
            f"{BASE_URL}/api/dashboard/performance",
            cookies=cookies
        )
        
        print(f"📊 Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"📊 Success: {data.get('success')}")
            print(f"📊 Data length: {len(data.get('data', []))}")
            print(f"📊 Filters: {data.get('filters', {})}")
            
            # Mostrar algumas assinaturas
            print(f"\n📝 Primeiras 10 assinaturas:")
            for i, emp in enumerate(data.get('data', [])[:10]):
                print(f"   {i+1:2d}. {emp['name']}: {emp['rncs']} RNCs")
        else:
            print(f"❌ Erro: {response.text}")
            
    except Exception as e:
        print(f"❌ Erro ao testar dashboard API: {e}")

def test_api_with_filters(cookies):
    """Testar API com filtros específicos"""
    print("\n🔍 Testando API com filtros específicos...")
    
    try:
        # Testar com filtro de ano 2025
        response = requests.get(
            f"{BASE_URL}/api/employee-performance",
            cookies=cookies,
            params={"year": "2025"}
        )
        
        print(f"📊 Status com filtro ano 2025: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"📊 Success: {data.get('success')}")
            print(f"📊 Data length: {len(data.get('data', []))}")
            print(f"📊 Filters: {data.get('filters', {})}")
            
            # Mostrar algumas assinaturas
            print(f"\n📝 Primeiras 10 assinaturas (ano 2025):")
            for i, emp in enumerate(data.get('data', [])[:10]):
                print(f"   {i+1:2d}. {emp['name']}: {emp['rncs']} RNCs")
        else:
            print(f"❌ Erro: {response.text}")
            
    except Exception as e:
        print(f"❌ Erro ao testar com filtros: {e}")

def main():
    """Função principal"""
    print("🚀 Testando API diretamente...")
    print(f"🌐 Servidor: {BASE_URL}")
    
    # Login
    cookies = test_api_direct()
    if not cookies:
        print("❌ Não foi possível fazer login")
        return
    
    # Testar APIs
    test_employee_performance_direct(cookies)
    test_dashboard_performance_direct(cookies)
    test_api_with_filters(cookies)
    
    print("\n✨ Testes concluídos!")

if __name__ == "__main__":
    main()
