$randomNumber = ((1..64 | .{Process{ Get-Random -InputObject ([char[]]"0123456789ABCDEF") }}) -join '')
$randomNumber = $randomNumber.ToLower()
$randomNumber
Read-Host -Prompt "Press Enter to exit"