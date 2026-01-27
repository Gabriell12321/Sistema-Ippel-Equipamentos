#!/usr/bin/env python3
"""
Teste rápido da nova API de engenharia
"""
import requests
import json

def test_engineering_api():
    """Testa a nova API de engenharia"""
    
    # Primeiro fazer login
    session = requests.Session()
    
    login_data = {
        'email': 'admin@ippel.com.br',
        'password': 'admin123'
    }
    
    print("🔐 Fazendo login...")
    try:
        login_response = session.post('http://127.0.0.1:5001/login', data=login_data)
        print(f"Login Status: {login_response.status_code}")
        if login_response.status_code == 200:
            print("✅ Login realizado com sucesso")
            
            # Testar a API de engenharia
            print("🔧 Testando API de engenharia...")
            eng_response = session.get('http://127.0.0.1:5001/api/indicadores/engenharia')
            
            print(f"API Engenharia Status: {eng_response.status_code}")
            
            if eng_response.status_code == 200:
                data = eng_response.json()
                print("✅ API de engenharia funcionando!")
                print(f"📊 Success: {data.get('success')}")
                if 'stats' in data:
                    stats = data['stats']
                    print(f"📈 Total RNCs: {stats.get('total_rncs', 0)}")
                    print(f"📈 RNCs Finalizadas: {stats.get('finalized_rncs', 0)}")
                    print(f"💰 Valor Total: R$ {stats.get('total_value', 0):,.2f}")
                
                if 'monthly_trend' in data:
                    trend = data['monthly_trend']
                    print(f"📅 Dados mensais: {len(trend)} meses")
                    if trend:
                        print(f"📅 Último mês: {trend[-1].get('label')} - {trend[-1].get('count')} RNCs")
                
                print("\n🎯 DADOS RETORNADOS:")
                print(json.dumps(data, indent=2, ensure_ascii=False))
                
            else:
                print(f"❌ Erro na API de engenharia: {eng_response.status_code}")
                print(eng_response.text)
        else:
            print(f"❌ Erro no login: {login_response.status_code}")
            print(login_response.text)
            
    except Exception as e:
        print(f"❌ Erro: {e}")

if __name__ == "__main__":
    test_engineering_api()