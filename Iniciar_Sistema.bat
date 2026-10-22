@echo off
title Sistema FUAs - Servidor Local
cd /d "D:\PROYECTOS PYTHON\CONTROL FUAS"
echo Iniciando el sistema de FUAs para la red local...
.venv\Scripts\python -m streamlit run app.py --server.address 0.0.0.0 --server.port 8501
pause