function Main {
    <#
    .SYNOPSIS
    The main function.
    
    .DESCRIPTION
    The main function executes all methods.
    
    .EXAMPLE
    Main
    #>
    [CmdletBinding()]
    param()

    Write-Host "#########################`nMSSQL audit tool`n#########################"

    # A stopwatch is used to check how long a section of the script has needed to be completed.
    # It is also used to check the total amount of time needed to complete the script.
    $Stopwatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $TotalTime = $Stopwatch.Elapsed
    $Stopwatch.Start()

    # Use the configurationfile if provided.
    # Configuration_Parser


    # Load the required imports.
    # Import-Module -Force ./Assets/Modules/MSSQL/Main/mssql.psm1

    # The password will not be visible while typing it in.
    if ($Script:SQLAuthentication) {
        $SecurePassword = Read-Host -AsSecureString "Enter password"
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $Script:Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }

    #Sets the output file. If the file already exists the user is prompted to override it or stop the script.
    $date = Get-Date -Format "yyyyMMdd"
    $Script:Outfile = "./Reports/" + $date + "-audit-report-" + $Script:Server + ".html"
    if (Test-Path -Path $Script:Outfile) {
        Write-Host "The output file already exists, would you like to overwrite it?"
        Remove-Item $Script:Outfile -Confirm
        if (Test-Path -Path $Script:Outfile) {
            Write-Host "Please move the output file: $Script:Outfile"
            exit
        }
    }
    HTMLPrinter -HTMLStart

    Write-Host "Using $Script:Server as target server"
    if ($Script:Database -ne "") {
        Write-Host "Using $Script:Database as target database"
        $Script:AllDatabases = $false
    }
    else {
        Write-Host "There Currently no database selected."
        Write-Host "Selecting database `"master`" for the connection string"
        $Script:Database = "master"
        $Script:AllDatabases = $true
    }

    HTMLPrinter -OpeningTag "<h1 id='Basic_information' class='headers header1'>" -Content "Basic information" -ClosingTag "</h1>"
    HTMLPrinter -OpeningTag "<p>" -Content "Using $Script:Server as target server." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Using $Script:Database as target database." -ClosingTag "</p>"

    $Script:OriginalDatabase = $Script:Database

    SqlConnectionBuilder    

    CheckFullVersion
    GenerateDatabasesInfo

    Write-Host "Setup completed in:                                  " $Stopwatch.Elapsed
    $TotalTime += $Stopwatch.Elapsed
    Write-Host "Total time elapsed:                                  " $TotalTime
    $Stopwatch.Restart()

    HTMLPrinter -HTMLEnd

    $TotalTime += $Stopwatch.Elapsed
    Write-Host "Audit has finished, total time elapsed:              " $TotalTime

    if ($Script:Include -eq 'All' -or $Script:Include -eq 'CIS') {
        SecurityChecklists

        Write-Host "CIS Microsoft SQL Server 2016 benchmark completed in:" $Stopwatch.Elapsed
        $TotalTime += $Stopwatch.Elapsed
        Write-Host "Total time elapsed:                                  " $TotalTime
        $Stopwatch.Restart()
    }

    if ($Script:Include -eq 'All' -or $Script:Include -eq 'UserManagement') {
        # Used to obtain all users and their rights.
        UserManagement

        Write-Host "User management completed in:                        " $Stopwatch.Elapsed
        $TotalTime += $Stopwatch.Elapsed
        Write-Host "Total time elapsed:                                  " $TotalTime
        $Stopwatch.Restart()
    }
}
