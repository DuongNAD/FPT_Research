# Script tự động nạp API Keys từ .env và chạy máy chủ

$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $rootDir ".env"
if (-Not (Test-Path $envFile)) {
    $envFile = Join-Path $rootDir ".env.example"
}

Write-Host "[ShieldAI] Dang nap API Keys tu file $(Split-Path $envFile -Leaf) ..." -ForegroundColor Cyan

foreach($line in Get-Content $envFile) {
    if ($line -match "^\s*#" -or $line -match "^\s*$") { continue }
    $parts = $line -split "=", 2
    if ($parts.Length -eq 2) {
        $key = $parts[0].Trim()
        $value = $parts[1].Trim("'`"")
        Set-Item -Path "env:$key" -Value $value
    }
}

Write-Host "[ShieldAI] Khoi dong he thong Backend Proxy..." -ForegroundColor Green

# Thiết lập rõ ràng môi trường ảo VENV cho hệ thống nhận diện
$env:VIRTUAL_ENV = Join-Path $rootDir "venv"
$env:PATH = "$(Join-Path $rootDir 'venv\Scripts');$env:PATH"

Set-Location $rootDir
# Khởi động thẳng bằng Python (đã kích hoạt qua PATH ảo)
python backend_api.py
