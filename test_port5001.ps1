#!/usr/bin/env pwsh
# Script para testar endpoints na porta 5001

Write-Host "`n=== TESTE DE ENDPOINTS - PORTA 5001 ===" -ForegroundColor Cyan
Write-Host "Este script testa se os endpoints estão respondendo corretamente" -ForegroundColor Yellow

$baseUrl = "https://rnc.ippel.com.br:5001"

Write-Host "`n1. Testando OPTIONS preflight (renumber)..." -ForegroundColor Green
try {
    $response = curl.exe -k -X OPTIONS "$baseUrl/api/rnc/34730/renumber" `
        -H "Access-Control-Request-Method: POST" `
        -H "Origin: $baseUrl" `
        -v 2>&1 | Select-String -Pattern "HTTP|200|405|403"
    Write-Host $response
} catch {
    Write-Host "Erro: $_" -ForegroundColor Red
}

Write-Host "`n2. Testando OPTIONS preflight (delete)..." -ForegroundColor Green
try {
    $response = curl.exe -k -X OPTIONS "$baseUrl/api/rnc/34730/permanent-delete" `
        -H "Access-Control-Request-Method: POST" `
        -H "Origin: $baseUrl" `
        -v 2>&1 | Select-String -Pattern "HTTP|200|405|403"
    Write-Host $response
} catch {
    Write-Host "Erro: $_" -ForegroundColor Red
}

Write-Host "`n3. Testando POST renumber (sem auth - esperado 401)..." -ForegroundColor Green
try {
    $response = curl.exe -k -X POST "$baseUrl/api/rnc/34730/renumber" `
        -H "Content-Type: application/json" `
        -H "Accept: application/json" `
        -d '{"new_number":"34731"}' `
        -v 2>&1 | Select-String -Pattern "HTTP|401|405|200"
    Write-Host $response
} catch {
    Write-Host "Erro: $_" -ForegroundColor Red
}

Write-Host "`n=== INSTRUÇÕES ===" -ForegroundColor Cyan
Write-Host "✅ Se ver 'HTTP/1.1 200' nos OPTIONS = Preflight funcionando"
Write-Host "✅ Se ver 'HTTP/1.1 401' no POST = Endpoint funcionando (precisa login)"
Write-Host "❌ Se ver 'HTTP/1.1 405' = Método ainda bloqueado"
Write-Host "`nPara testar com autenticação:" -ForegroundColor Yellow
Write-Host "1. Abra o browser em: $baseUrl"
Write-Host "2. Faça login normalmente"
Write-Host "3. Abra DevTools (F12) → Application → Cookies"
Write-Host "4. Copie o valor do cookie 'ippel_session'"
Write-Host "5. Execute:"
Write-Host '   curl.exe -k -X POST "' -NoNewline -ForegroundColor Gray
Write-Host "$baseUrl/api/rnc/34730/renumber" -NoNewline -ForegroundColor White
Write-Host '" \' -ForegroundColor Gray
Write-Host '     -H "Content-Type: application/json" \' -ForegroundColor Gray
Write-Host '     -H "Cookie: ippel_session=SEU_COOKIE_AQUI" \' -ForegroundColor Gray
Write-Host '     -d ' -NoNewline -ForegroundColor Gray
Write-Host '''{"new_number":"34731"}''' -ForegroundColor White
Write-Host ""
