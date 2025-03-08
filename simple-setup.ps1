# SavorAI User Service - Simple Setup Script
# Run this script with: .\simple-setup.ps1
# IMPORTANT: This script is for development use only. For production,
# use more secure methods like environment variables in your deployment environment.

# Clear previous environment variables (if any)
Remove-Item Env:JWT_SECRET -ErrorAction SilentlyContinue
Remove-Item Env:MAIL_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:DB_USERNAME -ErrorAction SilentlyContinue
Remove-Item Env:DB_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:MAIL_USERNAME -ErrorAction SilentlyContinue
Remove-Item Env:ACTUATOR_USERNAME -ErrorAction SilentlyContinue
Remove-Item Env:ACTUATOR_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:FRONTEND_URL -ErrorAction SilentlyContinue

# Default values - CHANGE THESE or set them interactively
$DB_USERNAME_DEFAULT = "root"
$DB_PASSWORD_DEFAULT = "changeme" # You should change this
$MAIL_USERNAME_DEFAULT = "your_email@gmail.com" # Change this
$ACTUATOR_USERNAME_DEFAULT = "actuator"
$FRONTEND_URL_DEFAULT = "http://localhost:5173"

# Interactive setup
Write-Host "========= SavorAI User Service Environment Setup =========" -ForegroundColor Cyan

$input_db_username = Read-Host "Database username [$DB_USERNAME_DEFAULT]"
$env:DB_USERNAME = if ([string]::IsNullOrWhiteSpace($input_db_username)) { $DB_USERNAME_DEFAULT } else { $input_db_username }

$input_db_password = Read-Host "Database password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($input_db_password)
$db_password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$env:DB_PASSWORD = if ([string]::IsNullOrWhiteSpace($db_password)) { $DB_PASSWORD_DEFAULT } else { $db_password }

$input_mail_username = Read-Host "Email username [$MAIL_USERNAME_DEFAULT]"
$env:MAIL_USERNAME = if ([string]::IsNullOrWhiteSpace($input_mail_username)) { $MAIL_USERNAME_DEFAULT } else { $input_mail_username }

$input_mail_password = Read-Host "Email password/app password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($input_mail_password)
$mail_password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$env:MAIL_PASSWORD = $mail_password

$input_actuator_username = Read-Host "Actuator username [$ACTUATOR_USERNAME_DEFAULT]"
$env:ACTUATOR_USERNAME = if ([string]::IsNullOrWhiteSpace($input_actuator_username)) { $ACTUATOR_USERNAME_DEFAULT } else { $input_actuator_username }

$input_actuator_password = Read-Host "Actuator password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($input_actuator_password)
$actuator_password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$env:ACTUATOR_PASSWORD = $actuator_password

$input_frontend_url = Read-Host "Frontend URL [$FRONTEND_URL_DEFAULT]"
$env:FRONTEND_URL = if ([string]::IsNullOrWhiteSpace($input_frontend_url)) { $FRONTEND_URL_DEFAULT } else { $input_frontend_url }

# Generate a random JWT secret for this development session
Write-Host "Generating secure JWT secret..." -ForegroundColor Yellow
if (Test-Path GenerateJwtSecret.class) {
    try {
        $generatedSecret = java GenerateJwtSecret | Select-String -Pattern "^([A-Za-z0-9+/]{43}=)$" | ForEach-Object { $_.Matches.Groups[1].Value }
        if ($generatedSecret) {
            $env:JWT_SECRET = $generatedSecret
            Write-Host "New JWT secret generated successfully!" -ForegroundColor Green
        } else {
            # Generate a fallback secret
            $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $bytes = New-Object byte[] 32
            $random.GetBytes($bytes)
            $env:JWT_SECRET = [Convert]::ToBase64String($bytes)
            Write-Host "Generated fallback JWT secret" -ForegroundColor Yellow
        }
    } catch {
        # Generate a fallback secret if Java fails
        $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[] 32
        $random.GetBytes($bytes)
        $env:JWT_SECRET = [Convert]::ToBase64String($bytes)
        Write-Host "Generated fallback JWT secret" -ForegroundColor Yellow
    }
} else {
    # Generate a fallback secret if Java class is missing
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    $random.GetBytes($bytes)
    $env:JWT_SECRET = [Convert]::ToBase64String($bytes)
    Write-Host "Generated fallback JWT secret" -ForegroundColor Yellow
    Write-Host "Compile GenerateJwtSecret.java for more options" -ForegroundColor Yellow
}

# Verify environment variables
Write-Host "`nEnvironment variables set:" -ForegroundColor Green
Write-Host "- DB_USERNAME: $env:DB_USERNAME" -ForegroundColor Cyan
Write-Host "- DB_PASSWORD: [HIDDEN]" -ForegroundColor Cyan
Write-Host "- JWT_SECRET: [SECURED]" -ForegroundColor Cyan
Write-Host "- MAIL_USERNAME: $env:MAIL_USERNAME" -ForegroundColor Cyan
Write-Host "- MAIL_PASSWORD: [HIDDEN]" -ForegroundColor Cyan
Write-Host "- ACTUATOR_USERNAME: $env:ACTUATOR_USERNAME" -ForegroundColor Cyan
Write-Host "- ACTUATOR_PASSWORD: [HIDDEN]" -ForegroundColor Cyan
Write-Host "- FRONTEND_URL: $env:FRONTEND_URL" -ForegroundColor Cyan

Write-Host "`nYour user service is ready!" -ForegroundColor Green
Write-Host "Run with: .\gradlew bootRun" -ForegroundColor Yellow
Write-Host "`nFor production deployment:" -ForegroundColor Yellow
Write-Host "1. Use a securely generated JWT token" -ForegroundColor Yellow
Write-Host "2. Set environment variables through your deployment platform" -ForegroundColor Yellow
Write-Host "3. Never store credentials in code repositories" -ForegroundColor Yellow 