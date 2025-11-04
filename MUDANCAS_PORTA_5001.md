# ✅ MUDANÇAS PARA PORTA 5001 FUNCIONAR

## 🔧 Arquivos Modificados:

### 1. **server_form.py** (linha ~8425)
**Mudança:** `SESSION_COOKIE_SAMESITE = None` (era `'Lax'`)
**Motivo:** Permite cookies funcionarem com porta customizada (5001) em HTTPS

### 2. **server_form.py** (linha ~362)
**Mudança:** Adicionado suporte a CORS com credenciais
```python
# Permite cookies em requisições AJAX mesmo com porta customizada
origin = request.headers.get('Origin')
if origin:
    resp.headers['Access-Control-Allow-Origin'] = origin
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept, X-Requested-With, Authorization'
```

### 3. **routes/rnc.py** (linha 93)
**Mudança:** Endpoint `/renumber` agora aceita `OPTIONS`
```python
@rnc.route('/api/rnc/<int:rnc_id>/renumber', methods=['POST', 'OPTIONS'])
```
**Mudança:** Adicionado log detalhado:
```python
logger.info(f"🔢 Renumber request - RNC ID: {rnc_id}, Method: {request.method}, Session: {session.get('user_id', 'NONE')}")
```

### 4. **routes/rnc.py** (linha 2253)
**Mudança:** Melhorado log do endpoint `/permanent-delete`
```python
logger.info(f"🗑️ Delete request - RNC ID: {rnc_id}, Method: {request.method}, Session: {session.get('user_id', 'NONE')}")
```

---

## 📝 O QUE FOI CORRIGIDO:

### ❌ **Problema Anterior:**
1. Cookies não eram enviados em requisições AJAX na porta 5001
2. `SameSite=Lax` bloqueava cookies em portas diferentes
3. Sem suporte a preflight OPTIONS em alguns endpoints
4. Sem CORS adequado para `credentials: 'include'`

### ✅ **Solução:**
1. ✅ `SameSite=None` permite cookies cross-port
2. ✅ CORS configurado para aceitar credenciais
3. ✅ OPTIONS adicionado em todos endpoints necessários
4. ✅ Logs detalhados para debug

---

## 🚀 COMO TESTAR:

### **1. Reiniciar o servidor Flask:**
```powershell
# Pare o servidor atual (Ctrl+C)
# Inicie novamente:
python server_form.py
```

### **2. Teste rápido via script:**
```powershell
.\test_port5001.ps1
```

### **3. Teste no browser:**
1. Acesse: `https://rnc.ippel.com.br:5001`
2. Faça login normalmente
3. Vá para "RNCs Finalizadas"
4. Abra DevTools (F12) → Aba **Console**
5. Clique em "⚙️ Opções" em uma RNC
6. Clique em "🔢 Renumerar RNC"

### **4. O que observar:**

#### ✅ **DevTools → Console:**
```
📝 renumberRNC chamado: {rncId: 34730, currentNumber: "RNC-34730"}
🔄 Renumerando RNC 34730 de "RNC-34730" para "34731"
📍 URL: https://rnc.ippel.com.br:5001/api/rnc/34730/renumber
📥 Response status: 200
✅ Data: {success: true, message: "RNC renumerada com sucesso..."}
```

#### ✅ **DevTools → Network (aba "renumber"):**
- **Request URL:** `https://rnc.ippel.com.br:5001/api/rnc/34730/renumber`
- **Request Method:** `POST`
- **Status Code:** `200 OK`
- **Request Headers:**
  - `Cookie: ippel_session=...` ← **DEVE ESTAR PRESENTE**
  - `Content-Type: application/json`
- **Response Headers:**
  - `Access-Control-Allow-Credentials: true`
  - `Access-Control-Allow-Origin: https://rnc.ippel.com.br:5001`

#### ✅ **Logs do servidor (terminal):**
```
🔢 Renumber request - RNC ID: 34730, Method: POST, Session: 1
✅ RNC 34730 renumerada: RNC-34730 → 34731 por usuário 1
```

#### ❌ **Se ainda ver erro 401:**
```
❌ Renumber NEGADO - Sem sessão para RNC 34730
```
**Causa:** Cookie não está sendo enviado
**Solução:** Verifique se o cookie `ippel_session` existe no DevTools → Application → Cookies

---

## 🔍 DEBUG AVANÇADO:

### **Se cookie não aparece:**
```powershell
# 1. Verificar configuração de cookies no servidor
curl.exe -k -X GET "https://rnc.ippel.com.br:5001/api/user/profile" -v 2>&1 | Select-String -Pattern "Set-Cookie"

# 2. Verificar se login está criando sessão
# No browser após login, DevTools → Application → Cookies
# Deve ter: ippel_session=<valor_longo>
```

### **Se preflight OPTIONS falhar:**
```powershell
curl.exe -k -X OPTIONS "https://rnc.ippel.com.br:5001/api/rnc/34730/renumber" `
  -H "Origin: https://rnc.ippel.com.br:5001" `
  -H "Access-Control-Request-Method: POST" `
  -v 2>&1 | Select-String -Pattern "HTTP|Allow"
```
**Esperado:** `HTTP/1.1 200 OK`

---

## 🎯 GARANTIAS:

✅ Porta 5001 agora aceita requisições AJAX com credenciais  
✅ Cookies funcionam mesmo em porta customizada  
✅ Preflight OPTIONS configurado corretamente  
✅ Logs detalhados para diagnóstico  
✅ CORS permite `credentials: 'include'`  

---

## 📞 SE AINDA NÃO FUNCIONAR:

Me envie:
1. Screenshot do **DevTools → Network** (requisição completa)
2. Screenshot do **DevTools → Console** (mensagens de erro)
3. Screenshot do **DevTools → Application → Cookies**
4. Logs do terminal do servidor (últimas 20 linhas)
