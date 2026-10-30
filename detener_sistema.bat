@echo off
echo Cerrando Sistema FUAs...

for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8501') do (
    taskkill /PID %%a /F >nul 2>&1
)

echo Sistema detenido.
timeout /t 2 >nul
exit