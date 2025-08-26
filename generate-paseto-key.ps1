# Generate a secure 32-byte key for PASETO
$bytes = New-Object byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
$key = [Convert]::ToBase64String($bytes)
Write-Host "Your PASETO Key (add to appsettings.json):" -ForegroundColor Green
Write-Host $key
