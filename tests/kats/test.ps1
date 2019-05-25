#! /usr/bin/env pwsh

$ErrorActionPreference = "Stop"

function New-TemporaryDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    $name = [System.IO.Path]::GetRandomFileName()
    New-Item -ItemType Directory -Path (Join-Path $parent "genkat.$name")
}

function Get-OSName {
    $osname = "Windows"
    if (Get-Command "uname" -errorAction SilentlyContinue) {
        $osname = $(uname)
    }
    return $osname
}

function Get-PSScriptRoot {
    $ScriptRoot = ""
    try {
        $ScriptRoot = Get-Variable -Name PSScriptRoot -ValueOnly -ErrorAction Stop
    } catch {
        $ScriptRoot = Split-Path $script:MyInvocation.MyCommand.Path
    }
    return $ScriptRoot
}

function CompareFiles($f1, $f2, $i) {
    $f1_content = $(Get-Content $f1)
    $f2_content = $(Get-Content $f2)

    if (Compare-Object $f1_content $f2_content) {
        Write-Host -NoNewline "ERROR"
        exit $i
    } else {
        Write-Host -NoNewline "OK"
    }
}

$help = @"
    Usage: test.sh [flags]

    Options:
        -h,--help: Display this help
        --genkat: Location of genkat binary
        -v,--verbose: Verbose output
"@

function parseOptions ($argv, $options) {
    $opts = @()
    if (!$argv) { return $null }

    foreach ($arg in $argv) {
        $test = ($arg -is [int]) -or
                ($arg -is [string]) -or
                ($arg -is [float])
        if (!$test) {
            Write-Host "Bad argument: $arg is not an integer, float, nor string." -ForegroundColor Red
            throw "Error: Bad Argument"
        }
        if ($arg -like '-*') {
            $opts += $arg
        }
    }

    if ($opts) {
        foreach ($opt in $opts) {
            switch ($opt) {
                {$PSItem -eq '--genkat'} {
                    $opt_value_i = $argv.IndexOf($opt) + 1;
                    $options.genkat = [string] $argv[$opt_value_i];
                    $argv.RemoveAt($opt_value_i)
                }
                {($PSItem -eq '-h') -or ($PSItem -eq '--help')} {
                    Write-Host $help -ForegroundColor Cyan;
                    break 1
                }
                {($PSItem -eq '-v') -or ($PSItem -eq '--verbose')} {
                    $options.verbose = [bool] 1
                }
                default {
                    Write-Host "Bad option: $opt is not a valid option." -ForegroundColor Red
                    throw "Error: Bad Option"
                }
            }
            $argv.Remove($opt)
        }
    }
    return [array]$argv,$options
}#fn

function main($argv) {

    $options = @{
        genkat = [string] ""
        help = [bool] 0
        verbose = [bool] 0
    }

    $argv,$optparsed = parseOptions $argv $options
    $scriptPath = Get-PSScriptRoot

    Set-Variable tempdir -option Constant -value $(New-TemporaryDirectory)

    $genkat = $options.genkat

    $i = 0
    foreach ($version in @(16, 19)) {
        foreach ($type in @("i", "d", "id")) {
            $i++

            if (19 -eq $version) {
                $kats = "argon2" + $type
            } else {
                $kats = "argon2" + $type + "_v" + $version
            }

            & $genkat $type $version > "$tempdir\$kats"

            Write-Host -NoNewline "Argon2$type  `tv=$version`: `t"
            CompareFiles $tempdir\$kats $scriptPath\$kats $i
            Write-Output ""
        }
    }

    if (Test-Path $tempdir) {
        Remove-Item -Recurse $tempdir
    }
}

main $(New-Object System.Collections.ArrayList(,$args))
