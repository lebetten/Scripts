Get-ChildItem "G:\Sub_Appl_Data\Techlog\BE_Cased_Hole_Group\" -Recurse -Depth 2 -ErrorAction SilentlyContinue -ErrorVariable gci_errors | ForEach-Object {

    $_ | Get-Acl -ErrorAction SilentlyContinue -ErrorVariable gacl_errors
}

$gci_errors | Select-Object -ExpandProperty CategoryInfo | Export-Csv -NoTypeInformation -Path C:\Temp\gci_errors.csv 
$gacl_errors | Select-Object -ExpandProperty CategoryInfo | Export-Csv -NoTypeInformation -Path C:\Temp\gacl_errors.csv