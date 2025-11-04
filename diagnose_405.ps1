#!/usr/bin/env pwsh
# Script para diagnosticar de onde vem o erro 405

Write-Host "`n=== DIAGNÓSTICO COMPLETO - ERRO 405 ===" -ForegroundColor Cyan

Write-Host "`n1️⃣ Testando DIRETAMENTE o Flask (porta 5001)..." -ForegroundColor Yellow
Write-Host "   URL: https://rnc.ippel.com.br:5001/api/rnc/34730/renumber" -ForegroundColor Gray

$result1 = curl.exe -k -X POST "https://rnc.ippel.com.br:5001/api/rnc/34730/renumber" `
    -H "Content-Type: application/json" `
    -H "Accept: application/json" `
    -d '{"new_number":"34731"}' `
    -i 2>&1

$status1 = $result1 | Select-String -Pattern "^HTTP/1\.[01] \d+"
Write-Host "   Status: $status1" -ForegroundColor $(if ($status1 -match "401") { "Green" } else { "Red" })

if ($status1 -match "405") {
    Write-Host "   ❌ ERRO: Flask retornando 405 (NÃO DEVERIA)" -ForegroundColor Red
    Write-Host "   Detalhes:" -ForegroundColor Gray
    $result1 | Select-String -Pattern "Allow:|Server:" | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
} elseif ($status1 -match "401") {
    Write-Host "   ✅ OK: Flask retornando 401 (endpoint funciona, precisa login)" -ForegroundColor Green
}

Write-Host "`n2️⃣ Testando via Nginx (porta 443)..." -ForegroundColor Yellow
Write-Host "   URL: https://rnc.ippel.com.br/api/rnc/34730/renumber" -ForegroundColor Gray

$result2 = curl.exe -k -X POST "https://rnc.ippel.com.br/api/rnc/34730/renumber" `
    -H "Content-Type: application/json" `
    -H "Accept: application/json" `
    -d '{"new_number":"34731"}' `
    -i 2>&1

$status2 = $result2 | Select-String -Pattern "^HTTP/1\.[01] \d+"
Write-Host "   Status: $status2" -ForegroundColor $(if ($status2 -match "401") { "Green" } elseif ($status2 -match "405") { "Red" } else { "Yellow" })

if ($status2 -match "405") {
    Write-Host "   ❌ PROBLEMA: Nginx retornando 405" -ForegroundColor Red
    Write-Host "   Detalhes:" -ForegroundColor Gray
    $result2 | Select-String -Pattern "Allow:|Server:|nginx" | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
} elseif ($status2 -match "401") {
    Write-Host "   ✅ OK: Nginx permitindo POST (retorna 401 do Flask)" -ForegroundColor Green
}

Write-Host "`n3️⃣ Verificando endpoint OPTIONS (preflight)..." -ForegroundColor Yellow

$result3 = curl.exe -k -X OPTIONS "https://rnc.ippel.com.br:5001/api/rnc/34730/renumber" `
    -H "Origin: https://rnc.ippel.com.br:5001" `
    -H "Access-Control-Request-Method: POST" `
    -i 2>&1

$status3 = $result3 | Select-String -Pattern "^HTTP/1\.[01] \d+"
Write-Host "   Status: $status3" -ForegroundColor $(if ($status3 -match "200") { "Green" } else { "Red" })

$allow3 = $result3 | Select-String -Pattern "Allow:|Access-Control"
if ($allow3) {
    Write-Host "   Headers CORS:" -ForegroundColor Gray
    $allow3 | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
}

Write-Host "`n4️⃣ Verificando rotas Flask..." -ForegroundColor Yellow
$routes = curl.exe -k "https://rnc.ippel.com.br:5001/__debug/routes" 2>&1 | ConvertFrom-Json

$renumberRoute = $routes.routes | Where-Object { $_.rule -eq "/api/rnc/<int:rnc_id>/renumber" }
if ($renumberRoute) {
    Write-Host "   ✅ Rota encontrada:" -ForegroundColor Green
    Write-Host "      Endpoint: $($renumberRoute.endpoint)" -ForegroundColor Gray
    Write-Host "      Methods: $($renumberRoute.methods -join ', ')" -ForegroundColor Gray
} else {
    Write-Host "   ❌ Rota NÃO encontrada!" -ForegroundColor Red
}

Write-Host "`n5️⃣ Testando com método GET (deve dar 405)..." -ForegroundColor Yellow
$result5 = curl.exe -k -X GET "https://rnc.ippel.com.br:5001/api/rnc/34730/renumber" `
    -i 2>&1

$status5 = $result5 | Select-String -Pattern "^HTTP/1\.[01] \d+"
Write-Host "   Status: $status5" -ForegroundColor Gray
Write-Host "   $(if ($status5 -match "405") { "✅ Correto: GET não permitido" } else { "⚠️ Inesperado" })" -ForegroundColor $(if ($status5 -match "405") { "Green" } else { "Yellow" })

Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
Write-Host "📊 RESUMO DO DIAGNÓSTICO" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan

if ($status1 -match "401" -and $renumberRoute) {
    Write-Host "`n✅ FLASK ESTÁ OK (porta 5001)" -ForegroundColor Green
    Write-Host "   - Endpoint registrado corretamente" -ForegroundColor Green
    Write-Host "   - Aceita POST (retorna 401 sem sessão)" -ForegroundColor Green
    Write-Host "   - Methods: $($renumberRoute.methods -join ', ')" -ForegroundColor Green
    
    if ($status2 -match "405") {
        Write-Host "`n❌ PROBLEMA: NGINX (porta 443)" -ForegroundColor Red
        Write-Host "   - Nginx está bloqueando o método POST" -ForegroundColor Red
        Write-Host "   - Verifique nginx.conf location /api/" -ForegroundColor Red
        Write-Host "   - Comando: Get-Content nginx\nginx.conf | Select-String -Pattern 'location /api/'" -ForegroundColor Yellow
    } elseif ($status2 -match "401") {
        Write-Host "`n✅ NGINX ESTÁ OK (porta 443)" -ForegroundColor Green
    }
    
    Write-Host "`n🔍 PRÓXIMO PASSO:" -ForegroundColor Cyan
    Write-Host "   Abra o browser em: https://rnc.ippel.com.br:5001" -ForegroundColor White
    Write-Host "   Abra DevTools (F12) → Aba Console" -ForegroundColor White
    Write-Host "   Tente renumerar e veja os logs:" -ForegroundColor White
    Write-Host "   - 📍 Location href: (deve ser :5001)" -ForegroundColor White
    Write-Host "   - 📥 Response URL: (confirma qual endpoint responde)" -ForegroundColor White
    
} else {
    Write-Host "`n❌ PROBLEMA NO FLASK" -ForegroundColor Red
    if ($status1 -match "405") {
        Write-Host "   - Flask retornando 405 para POST" -ForegroundColor Red
        Write-Host "   - Verifique se o servidor foi reiniciado" -ForegroundColor Yellow
        Write-Host "   - Verifique routes/rnc.py linha 93" -ForegroundColor Yellow
    } elseif (-not $renumberRoute) {
        Write-Host "   - Rota não registrada no Flask" -ForegroundColor Red
        Write-Host "   - Blueprint rnc não foi importado?" -ForegroundColor Yellow
    }
}

Write-Host ""
