$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root

try {
    Write-Host "== [1/5] Python 源码语法编译检查 (py_compile) ==" -ForegroundColor Cyan
    $pyFiles = Get-ChildItem -Recurse -Filter "*.py" -Path $Root | Where-Object { $_.FullName -notmatch "\\runs\\|\\__pycache__\\|\\\.venv\\" }
    foreach ($f in $pyFiles) {
        python -m py_compile $f.FullName
        if ($LASTEXITCODE -ne 0) { throw "Syntax check failed: $($f.FullName)" }
    }

    Write-Host "== [2/5] 初始沙盒公开业务冒烟自检 (smoke_check.py) ==" -ForegroundColor Cyan
    python "src/sandbox_template/smoke_check.py"
    if ($LASTEXITCODE -ne 0) { throw "Template smoke_check failed" }

    Write-Host "== [3/5] 计分公式、防篡改缓存与隔离单元测试 (test_scoring_units.py) ==" -ForegroundColor Cyan
    python "tests/test_scoring_units.py"
    if ($LASTEXITCODE -ne 0) { throw "Unit tests failed" }

    Write-Host "== [4/5] 仓库静态信任域隔离与目录卫生审计 (isolation_audit.py --strict) ==" -ForegroundColor Cyan
    python "tools/isolation_audit.py" --strict
    if ($LASTEXITCODE -ne 0) { throw "Repository isolation_audit failed" }

    Write-Host "== [5/5] 三基线端到端闭环与大梯度实测验证 (verify_three_baselines.py) ==" -ForegroundColor Cyan
    python "tests/verify_three_baselines.py"
    if ($LASTEXITCODE -ne 0) { throw "Three baselines verification failed" }

    Write-Host "`n[SMOKE SUCCESS] shield-turbo-xiaonuo 全部自检与三基线梯度核验 100% 通过！" -ForegroundColor Green
}
finally {
    Pop-Location
}
