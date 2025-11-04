#!/usr/bin/env pwsh
# Script para reiniciar o servidor Flask na porta 5001

Write-Host "`n=== REINICIAR SERVIDOR FLASK ===" -ForegroundColor Cyan

# 1. Encontrar processo Python rodando server_form.py
Write-Host "`n1. Procurando processo do servidor..." -ForegroundColor Yellow
$processes = Get-Process python* -ErrorAction SilentlyContinue | Where-Object { 
    $_.CommandLine -like "*server_form.py*" 
}

if ($processes) {
    Write-Host "   Encontrado(s) $($processes.Count) processo(s)" -ForegroundColor Green
    foreach ($proc in $processes) {
        Write-Host "   - PID: $($proc.Id)" -ForegroundColor Gray
    }
    
    $confirm = Read-Host "`nDeseja parar estes processos? (S/N)"
    if ($confirm -eq 'S' -or $confirm -eq 's') {
        foreach ($proc in $processes) {
            Stop-Process -Id $proc.Id -Force
            Write-Host "   ✅ Processo $($proc.Id) parado" -ForegroundColor Green
        }
        Start-Sleep -Seconds 2
    }
} else {
    Write-Host "   ℹ️ Nenhum processo encontrado" -ForegroundColor Yellow
}

# 2. Verificar se a porta 5001 está livre
Write-Host "`n2. Verificando porta 5001..." -ForegroundColor Yellow
$portInUse = Get-NetTCPConnection -LocalPort 5001 -ErrorAction SilentlyContinue

if ($portInUse) {
    Write-Host "   ⚠️ Porta 5001 ainda em uso!" -ForegroundColor Red
    $portInUse | ForEach-Object {
        Write-Host "   - PID: $($_.OwningProcess)" -ForegroundColor Gray
    }
    
    $confirm = Read-Host "`nDeseja forçar parar? (S/N)"
    if ($confirm -eq 'S' -or $confirm -eq 's') {
        $portInUse | ForEach-Object {
            Stop-Process -Id $_.OwningProcess -Force
        }
        Write-Host "   ✅ Processos parados" -ForegroundColor Green
        Start-Sleep -Seconds 2
    }
} else {
    Write-Host "   ✅ Porta 5001 livre" -ForegroundColor Green
}

# 3. Iniciar servidor
Write-Host "`n3. Iniciando servidor..." -ForegroundColor Yellow
Write-Host "   Comando: python server_form.py" -ForegroundColor Gray
Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "LOGS DO SERVIDOR:" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""

# Mudar para o diretório correto
Set-Location "Y:\RNC\repositoriornc-679d6de48201320bfb98a132ffc2b80b78499c9f"

# Iniciar servidor (vai rodar em primeiro plano)
python server_form.py
