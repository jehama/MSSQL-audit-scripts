$Outfile = "MSSQL_Audit.ps1"

$Script_sources = @(
    "src\Modules\MSSQL\Main\Manuals_and_params.ps1"
    "src\Modules\MSSQL\Main\SQL_data.ps1"
    "src\Modules\MSSQL\Main\Configuration_Parser.ps1"
    "src\Modules\MSSQL\Main\Main.ps1"
    "src\Modules\MSSQL\Main\SqlConnectionBuilder.ps1"
    "src\Modules\MSSQL\Main\DataCollector.ps1"
    "src\Modules\MSSQL\Info_Collector\Version_Checker.ps1"
    "src\Modules\MSSQL\Main\HTMLPrinter.ps1"
)

if (Test-Path -Path $Outfile) {
    Write-Host "The output file already exists, would you like to overwrite it?"
    Remove-Item $Outfile -Confirm
    if (Test-Path -Path $Outfile) {
        Write-Host "Please move the output file: $Outfile"
        exit
    }
}

foreach ($item in $Script_sources) {
    $content = Get-Content $item
    Add-Content -Path $Outfile -Value $content
    # Without this line the newline from the added content will be ignored and no newline will appear.
    Add-Content -Path $Outfile -Value `n
}

Add-Content -Path $Outfile -Value "Main"