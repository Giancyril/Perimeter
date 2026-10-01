# Autonomous SecOps Agent - Local Runner
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Starting Autonomous SecOps Agent (Local Development)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

Write-Host "`n[1/2] Launching FastAPI backend on http://localhost:8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000"

Write-Host "[2/2] Launching Vite Frontend on http://localhost:5173..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd frontend; npm run dev"

Write-Host "`nAll services started!" -ForegroundColor Yellow
Write-Host "  - SOC Dashboard:     http://localhost:5173" -ForegroundColor White
Write-Host "  - API Swagger Docs:  http://localhost:8000/docs" -ForegroundColor White
Write-Host "  - Health Check:      http://localhost:8000/health" -ForegroundColor White
