function CheckFullVersion {
    <#
    .SYNOPSIS
    Check the full version of the MSSQL Server.
    
    .DESCRIPTION
    Checks and displays the full version info of the MSSQL server.
    This includes the major version, service pack, build.
    
    .EXAMPLE
    CheckFullVersion
    #>
    [CmdletBinding()]

    $SqlQuery = "SELECT
                    @@VERSION AS Version
                ;"
    $Dataset = DataCollector $SqlQuery

    HTMLPrinter -OpeningTag "<h3 id='Server_version' class='headers'>" -Content "Server version" -ClosingTag "</h3>"
    HTMLPrinter -Table $Dataset -Columns @("Version")
}
