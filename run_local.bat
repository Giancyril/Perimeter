@echo off
echo ========================================================
echo Starting Autonomous SecOps Agent (Local Development)
echo ========================================================
echo.
echo 1. Starting FastAPI Backend on http://localhost:8000...
start "SecOps Backend (FastAPI)" cmd /k "uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000"

echo 2. Starting Frontend SOC Dashboard on http://localhost:5173...
start "SecOps Frontend (Vite)" cmd /k "cd frontend && npm run dev"

echo.
echo ========================================================
echo Services launched!
echo - SOC Dashboard:     http://localhost:5173
echo - API Documentation:   http://localhost:8000/docs
echo - API Health Check:   http://localhost:8000/health
echo ========================================================
pause
