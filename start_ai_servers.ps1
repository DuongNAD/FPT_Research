# SHIELDAI vLLM SERVER STARTER KIT
# NOTE ON RESOURCES (VRAM): 
# Qwen2.5-7B (Q4_K_M) requires ~ 5GB VRAM
# Gemma-2-9B (Q4_K_M) requires ~ 6.5GB VRAM

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "STARTING SHIELDAI LOCAL MULTI-AGENT SERVERS" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Start Gemma 2 (Defender - Port 8001) with LlamaCPP GGUF
Write-Host "`n[1/2] Loading GGUF Gemma-2-9B into Llama.cpp Engine..." -ForegroundColor Yellow
Start-Process -FilePath ".\venv\Scripts\python.exe" -ArgumentList "-m", "llama_cpp.server", "--model", "E:\Project\FPT_Research\AI_Models\Gemma-2-9B.gguf", "--port", "8001", "--n_gpu_layers", "-1", "--chat_format", "gemma", "--n_ctx", "4096" -NoNewWindow -RedirectStandardOutput "gemma_server.log" -RedirectStandardError "gemma_server_err.log" -PassThru

# Start Qwen 2.5 (Prosecutor - Port 8000) with LlamaCPP GGUF
Write-Host "`n[2/2] Loading GGUF Qwen2.5-7B into Llama.cpp Engine..." -ForegroundColor Yellow
Start-Process -FilePath ".\venv\Scripts\python.exe" -ArgumentList "-m", "llama_cpp.server", "--model", "E:\Project\FPT_Research\AI_Models\Qwen2.5-7B.gguf", "--port", "8000", "--n_gpu_layers", "-1", "--chat_format", "chatml", "--n_ctx", "8192" -NoNewWindow -RedirectStandardOutput "qwen_server.log" -RedirectStandardError "qwen_server_err.log" -PassThru

Write-Host "`n[SUCCESS] C++ API Engine is booting up... Please check the log files." -ForegroundColor Green
