param(
    [string]$Root = (Resolve-Path "$PSScriptRoot\..").Path
)

$ErrorActionPreference = "Stop"
$binDir = Join-Path $Root "bin"
if (!(Test-Path $binDir)) {
    New-Item -Path $binDir -ItemType Directory | Out-Null
}

Write-Host "[1/2] Building Rust memory ranker..."
cargo build --release --manifest-path (Join-Path $Root "rust\memory_ranker\Cargo.toml")
Copy-Item -Force (Join-Path $Root "rust\memory_ranker\target\release\memory_ranker.exe") (Join-Path $binDir "memory_ranker.exe")

Write-Host "[2/2] Building Go swarm planner..."
Push-Location (Join-Path $Root "go\swarm_planner")
go build -o (Join-Path $binDir "swarm_planner.exe") .
Pop-Location

Write-Host "Built accelerators in $binDir"
