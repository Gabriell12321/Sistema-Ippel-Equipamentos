"""
Script para limpar o cache do sistema RNC
"""
import os
import sys

# Adicionar o diretório raiz ao path
sys.path.insert(0, os.path.dirname(__file__))

try:
    from services.cache import clear_cache
    
    print("=" * 60)
    print("🗑️  LIMPANDO CACHE DO SISTEMA")
    print("=" * 60)
    
    result = clear_cache()
    
    if result:
        print("\n✅ Cache limpo com sucesso!")
    else:
        print("\n⚠️  Função de limpar cache não disponível ou cache vazio")
    
    print("=" * 60)
    
except ImportError as e:
    print("⚠️  Módulo de cache não encontrado, tentando manualmente...")
    print(f"   Erro: {e}")
    
    # Tentar limpar cache Redis manualmente
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        
        # Buscar chaves relacionadas a RNC
        keys = r.keys('rnc:*')
        if keys:
            r.delete(*keys)
            print(f"✅ {len(keys)} chaves de cache removidas do Redis!")
        else:
            print("ℹ️  Nenhuma chave de cache encontrada no Redis")
            
    except Exception as e2:
        print(f"⚠️  Redis não disponível: {e2}")
        print("ℹ️  O cache será limpo automaticamente em 2 minutos")

print("\n💡 DICA: Reinicie o servidor Flask para garantir que as mudanças sejam aplicadas!")
print("   E faça um hard refresh no navegador (Ctrl+Shift+R ou Ctrl+F5)\n")
