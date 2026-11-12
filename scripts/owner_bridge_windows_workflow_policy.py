#!/usr/bin/env python3
"""Reviewed complete native evidence graph and producer-program tripwires.

This literal is a deliberate independent policy oracle. Update it only when
reviewing a workflow change; CI never regenerates it from the workflow.
"""

from __future__ import annotations

import hashlib
import pathlib

from check_owner_runtime_custody_policy import PolicyError, load_workflow, same_graph

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ".github/workflows/owner-bridge-windows.yml"
NATIVE_COVERAGE_COMMAND = """$ErrorActionPreference = 'Stop'
$metadata = cargo metadata --locked --no-deps --format-version 1
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed' }
$metadata | Set-Content -Encoding utf8 "$env:RUNNER_TEMP/owner-windows-metadata.json"
$ignore = $metadata | python scripts/owner_bridge_windows_cov_ignore.py
if ($LASTEXITCODE -ne 0 -or -not $ignore) { throw 'Unsafe coverage scope' }
$marker = Join-Path $env:RUNNER_TEMP ("owner-desktop-stop-" + [guid]::NewGuid().ToString('N'))
$observer = $null
try {
  $observer = Start-Job -FilePath (Join-Path $env:GITHUB_WORKSPACE 'scripts/observe-owner-desktop.ps1') -ArgumentList $marker
} catch { Write-Output 'NATIVE_DESKTOP observer=unknown' }
try {
  cargo llvm-cov -p pos-owner-bridge-windows --all-features --locked --no-fail-fast --json --output-path "$env:RUNNER_TEMP/owner-windows-coverage.json" --ignore-filename-regex "$ignore" -- --include-ignored --nocapture
  $nativeResult = $LASTEXITCODE
} finally {
  try {
    [System.IO.File]::WriteAllText($marker, 'stop')
    if ($null -ne $observer) {
      $finished = Wait-Job -Job $observer -Timeout 6
      if ($null -eq $finished) { Write-Output 'NATIVE_DESKTOP observer_stop=unknown' }
      if ($observer.State -ne 'Completed') { Write-Output 'NATIVE_DESKTOP observer_state=unknown' }
      Receive-Job -Job $observer -ErrorAction SilentlyContinue
    }
  } catch { Write-Output 'NATIVE_DESKTOP observer_output=unknown' }
}
if ($nativeResult -ne 0) { throw 'Native coverage execution failed' }
"""

EXPECTED_NATIVE = {'name': 'owner-bridge-windows',
 True: {'workflow_call': None, 'workflow_dispatch': None},
 'permissions': {'contents': 'read'},
 'jobs': {'owner-bridge-windows': {'runs-on': 'windows-latest',
                                   'timeout-minutes': 60,
                                   'env': {'RUSTC_BOOTSTRAP': '1'},
                                   'steps': [{'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
                                              'with': {'fetch-depth': 0,
                                                       'persist-credentials': False}},
                                             {'uses': 'dtolnay/rust-toolchain@02cb101ec7c40f2c49e1d9714d64511d8e1b74de',
                                              'with': {'toolchain': '1.97.1',
                                                       'components': 'clippy,llvm-tools-preview'}},
                                             {'name': 'Install coverage producer',
                                              'uses': 'taiki-e/install-action@4cef1412cce204788f482e778a0b9187f9626a29',
                                              'with': {'tool': 'cargo-llvm-cov'}},
                                             {'name': 'Install coverage gate',
                                              'uses': 'taiki-e/install-action@4cef1412cce204788f482e778a0b9187f9626a29',
                                              'with': {'tool': 'covgate@0.2.0'}},
                                             {'name': 'Enforce the Windows unsafe inventory',
                                              'run': 'python '
                                                     'scripts/check_owner_bridge_unsafe_policy.py'},
                                             {'name': 'Lint native adapter and portable bridge',
                                              'run': 'cargo clippy -p pos-owner-bridge-windows -p '
                                                     'pos-owner-bridge -p piglor-owner --all-features '
                                                     '--all-targets --locked -- -D warnings -W '
                                                     'clippy::pedantic'},
                                             {'name': 'Prepare retained runtime for real native fixtures',
                                              'id': 'runtime',
                                              'shell': 'pwsh',
                                              'env': {'GH_TOKEN': '${{ github.token }}'},
                                              'run': './scripts/prepare-owner-runtime.ps1 -OutputRoot "$env:RUNNER_TEMP/owner-native-runtime"'},
                                             {'name': 'Test portable bridge, owner executable and native docs',
                                              'shell': 'pwsh',
                                              'env': {'OWNER_BRIDGE_TEST_RUNTIME': '${{ steps.runtime.outputs.runtime }}'},
                                              'run': "$ErrorActionPreference = 'Stop'\n"
                                                     'cargo test -p pos-owner-bridge -p piglor-owner --all-features --locked -- --include-ignored\n'
                                                     "if ($LASTEXITCODE -ne 0) { throw 'Portable bridge or owner executable tests failed' }\n"
                                                     'cargo test -p pos-owner-bridge-windows --all-features --locked --doc -- --include-ignored\n'
                                                     "if ($LASTEXITCODE -ne 0) { throw 'Native documentation tests failed' }\n"},
                                             {'name': 'Measure only shim source coverage',
                                              'id': 'coverage',
                                              'shell': 'pwsh',
                                              'env': {'OWNER_BRIDGE_TEST_RUNTIME': '${{ steps.runtime.outputs.runtime }}'},
                                              'run': NATIVE_COVERAGE_COMMAND},
                                             {'name': 'Enforce both changed-line Windows coverage '
                                                      'floors',
                                              'shell': 'pwsh',
                                              'env': {'COVERAGE_BASE': '${{ github.event_name == '
                                                                       "'pull_request' && "
                                                                       'github.event.pull_request.base.sha '
                                                                       '|| github.event_name == '
                                                                       "'push' && "
                                                                       'github.event.before || '
                                                                       "'origin/main' }}"},
                                              'working-directory': 'crates/pos-owner-bridge-windows',
                                              'run': 'covgate check '
                                                     '"$env:RUNNER_TEMP/owner-windows-coverage.json" '
                                                     '--base "$env:COVERAGE_BASE" '
                                                     '--no-github-summary'},
                                             {'name': 'Enforce both full-file Windows coverage '
                                                      'floors',
                                              'if': '${{ !cancelled() && steps.coverage.outcome == '
                                                    "'success' }}",
                                              'shell': 'pwsh',
                                              'run': "$ErrorActionPreference = 'Stop'\n"
                                                     '$metadata = Get-Content -Raw '
                                                     '"$env:RUNNER_TEMP/owner-windows-metadata.json"\n'
                                                     '$report = '
                                                     '"$env:RUNNER_TEMP/owner-windows-coverage.json"\n'
                                                     '$metadata | python '
                                                     'scripts/owner_bridge_windows_cov_ignore.py '
                                                     '--report "$report" --list-report\n'
                                                     "if ($LASTEXITCODE -ne 0) { throw 'Coverage "
                                                     "source scope is invalid' }\n"
                                                     '$safe = $metadata | python '
                                                     'scripts/owner_bridge_windows_cov_ignore.py '
                                                     '--report "$report" --scope safe\n'
                                                     'if ($LASTEXITCODE -ne 0 -or -not $safe) { '
                                                     "throw 'Unsafe full-file safe scope' }\n"
                                                     '$ffi = $metadata | python '
                                                     'scripts/owner_bridge_windows_cov_ignore.py '
                                                     '--report "$report" --scope ffi\n'
                                                     'if ($LASTEXITCODE -ne 0 -or -not $ffi) { '
                                                     "throw 'Unsafe full-file ffi scope' }\n"
                                                     'cargo llvm-cov report -p '
                                                     'pos-owner-bridge-windows --locked --json '
                                                     '--output-path '
                                                     '"$env:RUNNER_TEMP/owner-windows-safe-full.json" '
                                                     '--ignore-filename-regex "$safe" '
                                                     '--fail-under-lines 99 --fail-under-regions '
                                                     '99\n'
                                                     '$safeResult = $LASTEXITCODE\n'
                                                     'cargo llvm-cov report -p '
                                                     'pos-owner-bridge-windows --locked --json '
                                                     '--output-path '
                                                     '"$env:RUNNER_TEMP/owner-windows-ffi-full.json" '
                                                     '--ignore-filename-regex "$ffi" '
                                                     '--fail-under-lines 95 --fail-under-regions '
                                                     '80\n'
                                                     '$ffiResult = $LASTEXITCODE\n'
                                                     'if ($safeResult -ne 0 -or $ffiResult -ne 0) '
                                                     "{ throw 'Full-file Windows coverage floor "
                                                     "failed' }\n"},
                                             {'name': 'Export native LCOV for cargo-crap',
                                              'id': 'native-lcov',
                                              'if': '${{ !cancelled() && steps.coverage.outcome == '
                                                    "'success' }}",
                                              'shell': 'pwsh',
                                              'run': "$ErrorActionPreference = 'Stop'\n"
                                                     '$rawMetadata = Get-Content -Raw '
                                                     '"$env:RUNNER_TEMP/owner-windows-metadata.json"\n'
                                                     '$metadata = $rawMetadata | ConvertFrom-Json\n'
                                                     '$ignore = $rawMetadata | python '
                                                     'scripts/owner_bridge_windows_cov_ignore.py\n'
                                                     'if ($LASTEXITCODE -ne 0 -or -not $ignore) { '
                                                     "throw 'Unsafe native LCOV scope' }\n"
                                                     'cargo llvm-cov report -p '
                                                     'pos-owner-bridge-windows --locked --lcov '
                                                     '--no-default-ignore-filename-regex '
                                                     '--ignore-filename-regex "$ignore" '
                                                     '--output-path '
                                                     '"$env:RUNNER_TEMP/owner-windows.lcov"\n'
                                                     "if ($LASTEXITCODE -ne 0) { throw 'Native "
                                                     "LCOV export failed' }\n"
                                                     '$checkout = git rev-parse HEAD\n'
                                                     'if ($LASTEXITCODE -ne 0 -or $checkout -cne '
                                                     "$env:GITHUB_SHA) { throw 'Native coverage "
                                                     "checkout mismatch' }\n"
                                                     '$rustupRoot = rustup show home\n'
                                                     'if ($LASTEXITCODE -ne 0 -or -not '
                                                     "$rustupRoot) { throw 'Rustup source root is "
                                                     "unavailable' }\n"
                                                     '[ordered]@{\n'
                                                     '  version = 1\n'
                                                     '  checkout = $checkout\n'
                                                     '  workspace_root = $metadata.workspace_root\n'
                                                     '  target_directory = '
                                                     '$metadata.target_directory\n'
                                                     '  cargo_home = $env:CARGO_HOME\n'
                                                     '  rustup_home = $rustupRoot\n'
                                                     '  lcov_sha256 = (Get-FileHash -LiteralPath '
                                                     '"$env:RUNNER_TEMP/owner-windows.lcov" '
                                                     '-Algorithm SHA256).Hash.ToLowerInvariant()\n'
                                                     '} | ConvertTo-Json | Set-Content '
                                                     '-LiteralPath '
                                                     '"$env:RUNNER_TEMP/owner-windows-lcov-receipt.json" '
                                                     '-Encoding utf8\n'},
                                             {'name': 'Retain native LCOV and checkout receipt',
                                              'if': '${{ !cancelled() && steps.native-lcov.outcome '
                                                    "== 'success' }}",
                                              'uses': 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
                                              'with': {'name': 'owner-windows-lcov-${{ github.sha '
                                                               '}}',
                                                       'path': '${{ runner.temp '
                                                               '}}/owner-windows.lcov\n'
                                                               '${{ runner.temp '
                                                               '}}/owner-windows-lcov-receipt.json\n',
                                                       'if-no-files-found': 'error'}},
                                             {'name': 'Retain the measured shim report',
                                              'if': '${{ !cancelled() && steps.coverage.outcome == '
                                                    "'success' }}",
                                              'uses': 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
                                              'with': {'name': 'owner-windows-coverage-${{ '
                                                               'github.sha }}',
                                                       'path': '${{ runner.temp '
                                                               '}}/owner-windows-coverage.json\n'
                                                               '${{ runner.temp '
                                                               '}}/owner-windows-safe-full.json\n'
                                                               '${{ runner.temp '
                                                               '}}/owner-windows-ffi-full.json\n',
                                                       'if-no-files-found': 'error'}}]}}}

# Independently reviewed failure-only diagnostics; never accepted by the gates.
EXPECTED_NATIVE["jobs"]["owner-bridge-windows"]["steps"].extend([{'name': 'Export failed native coverage diagnostics',
  'if': "${{ failure() && !cancelled() && steps.coverage.outcome == 'failure' }}",
  'shell': 'pwsh',
  'run': "$ErrorActionPreference = 'Stop'\n"
         "$directory = Join-Path $env:RUNNER_TEMP 'owner-windows-failed-diagnostic'\n"
         'New-Item -ItemType Directory -Path $directory -Force | Out-Null\n'
         '$receipt = [ordered]@{\n'
         '  version = 1\n'
         "  qualification = 'failed-measurement-diagnostic-only'\n"
         '  expected_checkout = $env:GITHUB_SHA\n'
         '  checkout = $null\n'
         "  cargo_llvm_cov_version = 'unavailable'\n"
         '  profile_directory = $null\n'
         '  profile_files = 0\n'
         "  json = 'unavailable'\n"
         "  lcov = 'unavailable'\n"
         "  detail = 'profile unavailable'\n"
         '}\n'
         'try {\n'
         '  $checkout = git rev-parse HEAD\n'
         '  $receipt.checkout = $checkout\n'
         "  if ($LASTEXITCODE -ne 0 -or $checkout -cne $env:GITHUB_SHA) { throw 'checkout "
         "mismatch' }\n"
         '  $version = cargo llvm-cov --version\n'
         '  if ($LASTEXITCODE -eq 0 -and $version) { $receipt.cargo_llvm_cov_version = $version }\n'
         '  $rawMetadata = Get-Content -Raw "$env:RUNNER_TEMP/owner-windows-metadata.json"\n'
         '  $metadata = $rawMetadata | ConvertFrom-Json\n'
         '  $ignore = $rawMetadata | python scripts/owner_bridge_windows_cov_ignore.py\n'
         "  if ($LASTEXITCODE -ne 0 -or -not $ignore) { throw 'coverage scope unavailable' }\n"
         "  $targetOverride = [Environment]::GetEnvironmentVariable('CARGO_LLVM_COV_TARGET_DIR')\n"
         '  $profileDirectory = if ($null -ne $targetOverride) {\n'
         '    [System.IO.Path]::GetFullPath($targetOverride, (Get-Location).Path)\n'
         '  } else {\n'
         "    Join-Path $metadata.target_directory 'llvm-cov-target'\n"
         '  }\n'
         '  $receipt.profile_directory = $profileDirectory\n'
         "  $profiles = @(Get-ChildItem -LiteralPath $profileDirectory -Filter '*.profraw' -File | "
         'Where-Object { $_.Length -gt 0 })\n'
         '  $receipt.profile_files = $profiles.Count\n'
         "  if ($profiles.Count -eq 0) { throw 'profile unavailable' }\n"
         '  cargo llvm-cov report -p pos-owner-bridge-windows --locked --json '
         '--ignore-filename-regex "$ignore" --output-path "$directory/diagnostic.json"\n'
         '  if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath "$directory/diagnostic.json") '
         '-and (Get-Item -LiteralPath "$directory/diagnostic.json").Length -gt 0) { $receipt.json '
         "= 'available' }\n"
         '  cargo llvm-cov report -p pos-owner-bridge-windows --locked --lcov '
         '--no-default-ignore-filename-regex --ignore-filename-regex "$ignore" --output-path '
         '"$directory/diagnostic.lcov"\n'
         '  if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath "$directory/diagnostic.lcov") '
         '-and (Get-Item -LiteralPath "$directory/diagnostic.lcov").Length -gt 0) { $receipt.lcov '
         "= 'available' }\n"
         "  $receipt.detail = 'export attempted; available reports reflect failed test execution "
         "and are not qualification evidence'\n"
         '} catch {\n'
         '  $receipt.detail = "diagnostic export unavailable: $($_.Exception.Message)"\n'
         '} finally {\n'
         "  if ($receipt.json -ne 'available') { Remove-Item -LiteralPath "
         '"$directory/diagnostic.json" -ErrorAction SilentlyContinue }\n'
         "  if ($receipt.lcov -ne 'available') { Remove-Item -LiteralPath "
         '"$directory/diagnostic.lcov" -ErrorAction SilentlyContinue }\n'
         '  $receipt | ConvertTo-Json | Set-Content -LiteralPath "$directory/failure-receipt.json" '
         '-Encoding utf8\n'
         '}\n'},
 {'name': 'Retain failed native coverage diagnostics',
  'if': "${{ failure() && !cancelled() && steps.coverage.outcome == 'failure' }}",
  'uses': 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
  'with': {'name': 'owner-windows-failed-diagnostic-${{ github.sha }}',
           'path': '${{ runner.temp }}/owner-windows-failed-diagnostic/',
           'if-no-files-found': 'error'}}])

PRODUCER_SHA256 = {'scripts/check_owner_bridge_unsafe_policy.py': 'd449e3c747e79f3854a203da4cb1cfd2d376825596e6c72cf3c97235e6e6160f',
 'scripts/owner_bridge_windows_cov_ignore.py': '82f97a7eb43588f05c469fe72d22c78c4a78d56f0033e6b25cc6277a8f3f24a6',
 'scripts/observe-owner-desktop.ps1': '5d0999f0ced7700148ed6fd3a7b0e1b44a5c242067af36488b1dd7bda13ce77d'}


def producer_sources(root=ROOT):
    return {name: (root / name).read_text(encoding="utf-8") for name in PRODUCER_SHA256}


def check(native, sources=None):
    if not same_graph(native, EXPECTED_NATIVE):
        raise PolicyError("native evidence execution graph differs from the reviewed policy")
    sources = producer_sources() if sources is None else sources
    if sources.keys() != PRODUCER_SHA256.keys():
        raise PolicyError("native evidence producer set changed")
    for name, expected in PRODUCER_SHA256.items():
        if hashlib.sha256(sources[name].encode("utf-8")).hexdigest() != expected:
            raise PolicyError(f"native evidence producer differs from reviewed program: {name}")


def check_repository(root=ROOT):
    check(load_workflow((root / WORKFLOW).read_text(encoding="utf-8")), producer_sources(root))
