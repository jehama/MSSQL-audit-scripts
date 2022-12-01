<#
.SYNOPSIS
Audits the MSSQL Server against the CIS-benchmark, and looks at all users, roles and their rights.

.DESCRIPTION
This scripts checks the recommendations of the CIS-benchmark for MSSQL Server 2016 and MSSQL Server 2012 against the current configuration of the MSSQL Server.
It will also display the following information from the database:
    * The databases on the MSSQL Server, the date and time they were created, and the number of users each database has..
    * The logins and their corresponding database accounts.
    * The roles that are defined, both on server and database level.
    * The rights granted or denied to users and roles, both on server and database level.

.PARAMETER Server
Specifies the MSSQL Server to connect to.

.PARAMETER Database
Specifies the database to connect to.
This parameter is optional. If no database is selected it will default to auditing all available databases.

.PARAMETER WindowsAuthentication
Specifies to use Windows Authentication when connecting to the MSSQL Server.

.PARAMETER SQLAuthentication
Specifies to use SQL Authentication when connecting to the MSSQL Server.

.PARAMETER Username
Specifies the username to use when authenticating to the MSSQL Server.
This parameter is only used when authenticating with SQL Authentication.

.PARAMETER Include
Specifies which sections of the script to run.
This parameter is optional. If it is not used the default 'All' will be used.
Valid options are: 'All', 'CIS', 'STIG', 'UserManagement'.

.PARAMETER NoCsvOutput
Specifies whether to create CSV files or not. Default true.

.PARAMETER Version
Specifies which mssql server version the server is running, 
e.g. 2012 = 12, 2016 = 16. Defaulting to the latest.

.INPUTS
None.

.OUTPUTS
The output is saved in a HTML file.
This file will be saved in the same folder the script is run from.

.EXAMPLE
.\MSSQL_Audit_Script.ps1 -Server "Servername" -WindowsAuthentication

.EXAMPLE
.\MSSQL_Audit_Script.ps1 -Server "Servername" -SQLAuthentication -Username "test"

.EXAMPLE
.\MSSQL_Audit_Script.ps1 -Server "Servername" -Database "DatabaseName" -WindowsAuthentication

.EXAMPLE
.\MSSQL_Audit_Script.ps1 -Server "Servername" -Include "CIS,UserManagement" -WindowsAuthentication
#>

[CmdletBinding()]
# This initializes the parameters which were present when the script was launched.
param(
    # Specifies the MSSQL Server to connect to.
    [parameter(ParameterSetName = "WindowsAuthentication", Mandatory = $true)]
    [parameter(ParameterSetName = "SQLAuthentication", Mandatory = $true)]
    [String]
    $Server,

    # Specifies the database to connect to.
    # This parameter is optional. If no database is selected it will default to auditing all available databases.
    [parameter(ParameterSetName = "WindowsAuthentication")]
    [parameter(ParameterSetName = "SQLAuthentication")]
    [String]
    $Database,

    # Specifies to use Windows Authentication when connecting to the MSSQL Server.
    [parameter(ParameterSetName = "WindowsAuthentication", Mandatory = $true)]
    [switch]
    $WindowsAuthentication,

    # Specifies to use SQL Authentication when connecting to the MSSQL Server.
    [parameter(ParameterSetName = "SQLAuthentication", Mandatory = $true)]
    [switch]
    $SQLAuthentication,

    # Specifies the username to use when authenticating to the MSSQL Server.
    # This parameter is only used when authenticating with SQL Authentication.
    [parameter(ParameterSetName = "SQLAuthentication", Mandatory = $true)]
    [String]
    $Username,

    # Specifies the sections of the script to run.
    # This parameter is optional. If it is not used every section will be run.
    [parameter(ParameterSetName = "WindowsAuthentication")]
    [parameter(ParameterSetName = "SQLAuthentication")]
    [ValidateSet('All', 'CIS', 'STIG', 'UserManagement')]
    [String[]]
    $Include = 'All',

    # Parameter help description
    [parameter(ParameterSetName = "WindowsAuthentication")]
    [parameter(ParameterSetName = "SQLAuthentication")]
    [int]
    $Version = 19,

    # Specifies wether to create output CSVs.
    # This parameter is optional. If it is not set it will be true..
    [parameter(ParameterSetName = "WindowsAuthentication")]
    [parameter(ParameterSetName = "SQLAuthentication")]
    [switch]
    $NoCsvOutput
)

function Startup {
    <#
    .SYNOPSIS
    Method executed on startup.
    
    .DESCRIPTION
    This methods is called at the start of the program to verify it has started correctly.
    It also makes any necessary preparations.

    .EXAMPLE
    Startup
    #>

    # This statement is used to signal the start of the script.
    # It verifies that the script has started successfully.
    [CmdletBinding()]
    param()

    Write-Host "#########################`nMSSQL audit tool`n#########################"

    # A stopwatch is used to check how long a section of the script has needed to be completed.
    # It is also used to check the total amount of time needed to complete the script.
    $Script:Stopwatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $Script:TotalTime = $Script:Stopwatch.Elapsed
    $Script:Stopwatch.Start()

    # The password will not be visible while typing it in.
    if ($SQLAuthentication) {
        $SecurePassword = Read-Host -AsSecureString "Enter password"
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $Script:Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    
    $Script:StartTime = (Get-Date).ToString('MM-dd-yyyy-hh-mm')
    mkdir $Script:StartTime
    #Sets the output file. If the file already exists the user is prompted to override it or stop the script.
    $Script:Outfile = ".\$($Script:StartTime)\audit-MSSQL-" + $Script:Server + ".html"
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

    try {
        Write-Host "Testing Database connection."
        $Script:SqlConnection.Open()
    }
    catch {
        Write-Warning "Something went wrong while opening the connection."
        exit 1
        return
    }
    finally {
        $Script:SqlConnection.Close()
    }

    CheckFullVersion
    GenerateDatabasesInfo

    Write-Host "Setup completed in:                                  " $Script:Stopwatch.Elapsed
    $Script:TotalTime += $Script:Stopwatch.Elapsed
    Write-Host "Total time elapsed:                                  " $Script:TotalTime
    $Script:Stopwatch.Restart()

    Main

    HTMLPrinter -HTMLEnd

    $Script:TotalTime += $Script:Stopwatch.Elapsed
    Write-Host "Audit has finished, total time elapsed:              " $Script:TotalTime
}

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

    if ($Script:Include -eq 'All' -or $Script:Include -eq 'CIS') {
        SecurityChecklists

        Write-Host "CIS Microsoft SQL Server benchmark completed in:" $Script:Stopwatch.Elapsed
        $Script:TotalTime += $Script:Stopwatch.Elapsed
        Write-Host "Total time elapsed:                                  " $Script:TotalTime
        $Script:Stopwatch.Restart()
    }

    if ($Script:Include -eq 'All' -or $Script:Include -eq 'UserManagement') {
        # Used to obtain all users and their rights.
        UserManagement

        Write-Host "User management completed in:                        " $Script:Stopwatch.Elapsed
        $Script:TotalTime += $Script:Stopwatch.Elapsed
        Write-Host "Total time elapsed:                                  " $Script:TotalTime
        $Script:Stopwatch.Restart()
    }
}

function SqlConnectionBuilder {
    <#
    .SYNOPSIS
    Builds and returns the SqlConnection object.
    
    .DESCRIPTION
    Creates a ConnectionString based on the global script variables $Script:Server and $Script:Database.
    
    .EXAMPLE
    SqlConnectionBuilder
    #>
    [CmdletBinding()]

    # "Integrated Security = True" means that the connection uses windows authentication.
    # The supplied credentials will be the credentials of owner of the powershell session.
    $Script:SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    if ($WindowsAuthentication) {
        $Script:SqlConnection.ConnectionString = "Server = $Script:Server; Database = $Script:Database; Integrated Security = True;"
    }
    if ($SQLAuthentication) {
        $Script:SqlConnection.ConnectionString = "Server = $Script:Server; Database = $Script:Database; User Id = $Script:Username; Password = $Script:Password;"
    }
}

function DataCollector {
    <#
    .SYNOPSIS
    Collects data from the MSSQL instance.
    
    .DESCRIPTION
    Creates an SqlAdapter based on the SQL query and fills it with data.
    This dataset is then returned.
    
    .EXAMPLE
    SqlAdapter $SqlQuery
    #>
    [CmdletBinding()]
    [OutputType([System.Data.Dataset])]

    param (
        # The SQL query to run.
        [parameter(Mandatory = $true)]
        [String[]]
        $SqlQuery,

        [parameter()]
        [String]
        $AllTables
    )

    $SQLCommand = New-Object System.Data.SqlClient.SqlCommand
    $SQLCommand.CommandText = $SqlQuery
    $SQLCommand.Connection = $Script:SqlConnection
    $SQLAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
    $SQLAdapter.SelectCommand = $SQLCommand
    $Dataset = New-Object System.Data.DataSet
    $SqlAdapter.Fill($Dataset) | Out-Null


    if ($AllTables -eq "y") {
        , $Dataset
    }
    else {
        $DataTable = New-Object System.Data.DataTable
        $DataTable = $Dataset.Tables[0]

        , $DataTable
    }
}

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
                    @@VERSION AS Version, SERVERPROPERTY('MachineName') as Hostname
                ;"
    $Dataset = DataCollector $SqlQuery

    HTMLPrinter -OpeningTag "<h3 id='Server_version' class='headers'>" -Content "Server version" -ClosingTag "</h3>"
    HTMLPrinter -Table $Dataset -Columns @("Version", "Hostname")
    CsvWriter 'GEN-Version' "Version, Hostname"
    foreach ($Row in $Dataset) {
        CsvWriter 'GEN-Version' "$([string]::join('',($Row.Version.Split("`r?`n")))), $($Row.Hostname)"
    }
}

function GenerateDatabasesInfo {
    <#
    .SYNOPSIS
    Generate list of databases.
    
    .DESCRIPTION
    Generates a list of databases on the server.
    This list is used for queries that are used on every database on the server.
    
    .EXAMPLE
    GenerateDatabasesInfo
    
    .NOTES
    General notes
    #>
    [CmdletBinding()]
    
    param ()

    $SqlQuery = "SELECT
                    *
                FROM
                    sys.databases AS DB
                ;"
    $Script:DatabasesInfo = DataCollector $SqlQuery
    $Script:DatabasesInfo.Columns.Add("number_of_users", "System.String") | Out-Null

    $SqlQuery = "SELECT
                    COUNT(*) AS users
                FROM
                    sys.database_principals  AS DP
                WHERE
                    DP.type IN (
                        'C',
                        'E',
                        'G',
                        'K',
                        'S',
                        'U',
                        'X'
                    )
                ;"
    foreach ($db in $Script:DatabasesInfo) {
        $Script:Database = $db.name
        SqlConnectionBuilder
        $Dataset = DataCollector $SqlQuery
        $db.number_of_users = $Dataset.users
    }
    $Script:Database = $Script:OriginalDatabase
    SqlConnectionBuilder

    HTMLPrinter -OpeningTag "<h3 id='Databases' class='headers'>" -Content "Databases" -ClosingTag "</h3>"
    HTMLPrinter -Table $Script:DatabasesInfo -Columns @("name", "create_date", "number_of_users")
    CsvWriter 'GEN-Databases' "name,create_date,number_of_users"
    foreach ($Row in $Script:DatabasesInfo) {
        CsvWriter 'GEN-Databases' "$($Row.name),$($Row.create_date),$($Row.number_of_users)"
    }
}

function CsvWriter {
    param (
        # The SQL query to run.
        [parameter(Mandatory = $true)]
        [String]
        $FileName,

        [parameter(Mandatory = $true)]
        [String]
        $Text
    )
    $FileName = ".\$($Script:StartTime)\audit-MSSQL-" + $Script:Server + "-" + $FileName + ".CSV"
    if ($Script:NoCsvOutput) {
        # Empty switch to prevent CSV writing when the NoCsvOutput argument is present.
    }
    else {
        Add-Content $FileName $Text
    }
}

function ConvertTo-SQLHashString {
    <#
    .SYNOPSIS
    Converts SID back into the SID as seen in SSMS.
    
    .DESCRIPTION
    Converts SID back into the SID as seen in SSMS.
    Since it automatically is converted to a binary, therefor powershell can't show the value properly.
    
    .EXAMPLE
    ConvertTo-SQLHashString $sid
    
    .NOTES
    General notes
    #>
    [CmdletBinding()]
    [OutputType([String])]

    param([parameter(Mandatory = $true)] $binhash)
    $outstring = '0x'
    $binhash | ForEach-Object { $outstring += ('{0:X}' -f $_).PadLeft(2, '0') }
    return $outstring
}

function SecurityChecklists {
    <#
    .SYNOPSIS
    Checks the MSSQL server against checklists available on the NIST NCP repository.
    Currently these include:
    * CIS Microsoft SQL Server 2012 (1.4.0)
    * CIS Microsoft SQL Server 2016 (1.0.0)
    * Microsoft SQL Server 2016 STIG (Ver 1, Rel 4)
    
    .DESCRIPTION
    When checking the MSSQL server it will use the different parameters provided at the startup of the script to determine the checks to run.
    The options to test are currently CIS and STIG. It will use the latest implemented version based on version data of the server.
    Since not every check from the checklists can be performed on PowerShell this list is not complete.
    Checks that aren't supported will be noted so they can be checked manually.

    The CIS benchmark recommendatons are assigned a scoring status:
    Scored:     Failure to comply with "Scored" recommendations will decrease the final fenchmark score.
                Compliance with "Scored" recommendations will increase the final benchmark score.
    Not Scored: Failure to comply with "Not Scored" recommendations will not decrease the final benchmark score.
                Compliance with "Not Scored" recommendations will not increase the final benchmark score.

    The STIG policies are assigned a Severity Category Code (CAT):
    CAT I:   Any vulnerability, the exploitation of which will directly and immediately result in loss of Confidentiality, Availability, or Integrity.
    CAT II:  Any vulnerability, the exploitation of which has a potential to result in loss of Confidentiality, Availability, or Integrity.
    CAT III: Any vulnerability, the existence of which degrades measures to protect against loss of Confidentiality, Availability, or Integrity.

    This method can check any combination of CIS benchmark and STIG CAT checks.

    .EXAMPLE
    SecurityChecklists
    
    .NOTES
    The SecurityChecklists function does not check every MSSQL checklist found in the NIST NCP repository.
    It will only check MSSQL versions that are currently supported by Microsoft.

    The following checks can be performed by this function:

    CIS Microsoft SQL Server 2012 benchmark:
    * Section 1.1  (Not Scored)
    * Section 1.2  (Not Scored) (Manual)
    * Section 2.1  (Scored)
    * Section 2.2  (Scored)
    * Section 2.3  (Scored)
    * Section 2.4  (Scored)
    * Section 2.5  (Scored)
    * Section 2.6  (Scored)
    * Section 2.7  (Scored)
    * Section 2.8  (Scored)
    * Section 2.9  (Scored)
    * Section 2.10 (Not Scored) (Manual)
    * Section 2.11 (Scored)
    * Section 2.12 (Scored)
    * Section 2.13 (Scored)
    * Section 2.14 (Scored)
    * Section 2.15 (Scored)
    * Section 2.16 (Scored)
    * Section 2.17 (Scored)
    * Section 3.1  (Scored)
    * Section 3.2  (Scored)
    * Section 3.3  (Scored)
    * Section 3.4  (Scored)
    * Section 3.5  (Scored)     (Manual) Can this be automated?
    * Section 3.6  (Scored)     (Manual) Can this be automated?
    * Section 3.7  (Scored)     (Manual) Can this be automated? Net user and such?
    * Section 3.8  (Scored)
    * Section 3.9  (Scored)
    * Section 3.10 (Scored)
    * Section 3.11 (Scored)
    * Section 4.1  (Not Scored) (Manual)
    * Section 4.2  (Scored)
    * Section 4.3  (Scored)
    * Section 5.1  (Scored)
    * Section 5.2  (Scored)
    * Section 5.3  (Scored)
    * Section 5.4  (Scored)
    * Section 6.1  (Not Scored) (Manual)
    * Section 6.2  (Scored)
    * Section 7.1  (Scored)
    * Section 7.2  (Scored)
    * Section 8.1  (Not Scored) (Manual)

    CIS Microsoft SQL Server 2016 benchmark:
    * Section 1.1  (Not Scored)
    * Section 1.2  (Not Scored) (Manual)
    * Section 2.1  (Scored)
    * Section 2.2  (Scored)
    * Section 2.3  (Scored)
    * Section 2.4  (Scored)
    * Section 2.5  (Scored)
    * Section 2.6  (Scored)
    * Section 2.7  (Scored)
    * Section 2.8  (Scored)
    * Section 2.9  (Scored)
    * Section 2.10 (Not Scored) (Manual)
    * Section 2.11 (Scored)
    * Section 2.12 (Scored)
    * Section 2.13 (Scored)
    * Section 2.14 (Scored)
    * Section 2.15 (Scored)
    * Section 2.16 (Scored)
    * Section 2.17 (Scored)
    * Section 3.1  (Scored)
    * Section 3.2  (Scored)
    * Section 3.3  (Scored)
    * Section 3.4  (Scored)
    * Section 3.5  (Scored)     (Manual)
    * Section 3.6  (Scored)     (Manual)
    * Section 3.7  (Scored)     (Manual)
    * Section 3.8  (Scored)
    * Section 3.9  (Scored)
    * Section 3.10 (Scored)
    * Section 3.11 (Scored)
    * Section 4.1  (Not Scored) (Manual)
    * Section 4.2  (Scored)
    * Section 4.3  (Scored)
    * Section 5.1  (Scored)
    * Section 5.2  (Scored)
    * Section 5.3  (Scored)
    * Section 5.4  (Scored)
    * Section 6.1  (Not Scored) (Manual)
    * Section 6.2  (Scored)
    * Section 7.1  (Scored)
    * Section 7.2  (Scored)
    * Section 8.1  (Not Scored) (Manual)
    #>

    HTMLPrinter -OpeningTag "<h1 id='CIS_benchmark' class='headers'>" -Content "CIS benchmark" -ClosingTag "</h1>"

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 1.1.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 1.1.
    # Checks the productlevel and productversion.
    $SqlQuery = "SELECT
                    SERVERPROPERTY('ProductLevel') as SP_installed,
                    SERVERPROPERTY('ProductVersion') as version
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "The server contains the following Service Pack and Version. These can be found on microsofts website." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Check if these match the expected versions." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("SP_installed", "version")
    CsvWriter 'CIS-Version' "SP_installed,version"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Version' "$($Row.SP_installed),$($Row.version)"
    }
    
    

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.1.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.1.
    # Checks if the option 'Ad Hoc Distributed Queries' is disabled.
    $SqlQuery = "SELECT name                      AS name,
                        CAST(value AS int)        AS value_configured,
                        CAST(value_in_use AS int) AS value_in_use
                FROM
                    sys.configurations AS C
                WHERE
                    C.name = 'Ad Hoc Distributed Queries'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'Add Hoc Distributed Queries' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
    CsvWriter 'CIS-Compliance' "name,value_configured,value_in_use,expected,database"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0"
    }

    # This first query is based on CIS Microsoft SQL Server 2012 benchmark section 2.2.
    # This first query is based on CIS Microsoft SQL Server 2016 benchmark section 2.2.
    # This second query is based on CIS Microsoft SQL Server 2019 benchmark section 2.2 and 2.17.
    # Checks if the option 'clr enabled' is disabled or 'clr strict security' is enabled for 2019..
    $SqlQuery = ""
    $SqlQuery = "SELECT name                      AS name,
                    CAST(value AS int)        AS value_configured,
                    CAST(value_in_use AS int) AS value_in_use
            FROM
                sys.configurations AS C
            WHERE
                C.name = 'clr enabled'
            ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'clr enabled' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0"
    }
    # For 2019 (And above?) Only.
    if ($Script:AllDatabases) {
        foreach ($db in $Script:DatabasesInfo) {
            $SqlQuery = "
                SELECT 
                    name            AS name,
                    CAST(value as int)  as value_configured,
                    CAST(value_in_use   as int) as value_in_use
                FROM 
                    sys.configurations
                WHERE 
                    name = 'clr strict security';
            ;"
            $Script:Database = $db.name
            SqlConnectionBuilder
            $Dataset = DataCollector $SqlQuery
            if ($Dataset.Rows.Count -gt 0) {
                HTMLPrinter -OpeningTag "<p>" -Content "Check if 'clr strict security' is enabled (1) for $($db.name)." -ClosingTag "</p>"
                HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
                foreach ($Row in $Dataset) {
                    CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0,$($db.name)"
                }
            }
        }
        $Script:Database = $Script:OriginalDatabase
    }
    else {
        if ($Script:Version -ge 19) {
            $SqlQuery = "SELECT name            AS name,
                        CAST(value as int)  as value_configured,
                        CAST(value_in_use   as int) as value_in_use
                    FROM 
                        sys.configurations
                    WHERE 
                        name = 'clr strict security';
                    ;"
            $Dataset = DataCollector $SqlQuery
            HTMLPrinter -OpeningTag "<p>" -Content "Check if 'clr strict security' is enabled (1)." -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
            foreach ($Row in $Dataset) {
                CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0"
            }
        }
    }


    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.3.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.3.
    # Checks if the option 'cross db ownership chaining' is disabled.
    $SqlQuery = "SELECT name                      AS name,
                        CAST(value AS int)        AS value_configured,
                        CAST(value_in_use AS int) AS value_in_use
                FROM
                    sys.configurations AS C
                WHERE
                    C.name = 'cross db ownership chaining'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'cross db ownership chaining' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.4.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.4.
    # Checks if the option 'Database Mail XPs' is disabled.
    $SqlQuery = "SELECT name                      AS name,
                        CAST(value AS int)        AS value_configured,
                        CAST(value_in_use AS int) AS value_in_use
                FROM
                    sys.configurations AS C
                WHERE
                    C.name = 'Database Mail XPs'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'Database Mail XPs' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.5.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.5.
    # Checks if the option 'Ole Automation Procedures' is disabled.
    $SqlQuery = "SELECT name                      AS name,
                        CAST(value AS int)        AS value_configured,
                        CAST(value_in_use AS int) AS value_in_use
                FROM
                    sys.configurations AS C
                WHERE
                    C.name = 'Ole Automation Procedures'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'Ole Automation Procedures' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.6.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.6.
    # Checks if the option 'remote access' is disabled.
    $SqlQuery = "SELECT name                      AS name,
                        CAST(value AS int)        AS value_configured,
                        CAST(value_in_use AS int) AS value_in_use
                FROM
                    sys.configurations AS C
                WHERE
                    C.name = 'remote access'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'remote access' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.7.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.7.
    # Checks if the option 'remote admin connections' is disabled if the server is not in a cluster.
    $SqlQuery = "SELECT name                      AS name,
                        CAST(value AS int)        AS value_configured,
                        CAST(value_in_use AS int) AS value_in_use
                FROM
                    sys.configurations AS C
                WHERE
                      C.name                        = 'remote admin connections'
                  AND SERVERPROPERTY('IsClustered') = 0
                ;"
    $Dataset = DataCollector $SqlQuery
    if ($Dataset.Rows.Count -gt 0) {
        HTMLPrinter -OpeningTag "<p>" -Content "Check if 'remote admin connections' is disabled (0)." -ClosingTag "</p>"
        HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
    }
    else {
        HTMLPrinter -OpeningTag "<p>" -Content "This server is in a cluster. Therefore the check for 'remote admin connections' does not apply." -ClosingTag "</p>"
    }
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.8.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.8.
    # Checks if the option 'scan for startup procs' is disabled.
    $SqlQuery = "SELECT name                      AS name,
                        CAST(value AS int)        AS value_configured,
                        CAST(value_in_use AS int) AS value_in_use
                FROM
                    sys.configurations AS C
                WHERE
                    C.name = 'scan for startup procs'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'scan for startup procs' is disabled (0)" -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Note that this option might be enabled to use certain audit traces, stored procedures and replication." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.9.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.9.
    # Checks if the option 'is_trustworthy_on' is disabled.
    HTMLPrinter -OpeningTag "<p>" -Content "Check for the following databases if they have the (is_trustworthy_on set to False)." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "The 'msdb' database is required to have 'is_trustworthy_on set to True.`n" -ClosingTag "</p>"
    HTMLPrinter -Table $Script:DatabasesInfo -Columns @("name", "is_trustworthy_on")
    CsvWriter 'CIS-Trustworthy' "name,is_trustworthy_on"
    foreach ($Row in $Script:DatabasesInfo) {
        CsvWriter 'CIS-Trustworthy' "$($Row.name),$($Row.is_trustworthy_on)"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.11.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.11.
    # Checks if the MSSQL Server does not use the default port 1433.
    # Outdatedd but still works. Newer versions don't work when run from the machine it's hosted on.
    $SqlQuery = "DECLARE
                    @value nvarchar (256)
                ;

                EXECUTE
                    master.dbo.xp_instance_regread
                        N'HKEY_LOCAL_MACHINE',
                        N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib\Tcp\IPALL',
                        N'TcpPort',
                        @value OUTPUT,
                        N'no_output'
                ;
                    
                SELECT
                    @value AS TCP_port
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check that the server does not use the default TCP_Port 1433." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("TCP_port")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "TCP_port,$($Row.TCP_port),,Not 1433"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.12.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.12.
    # Checks if the server is hidden. If the server is in a cluster it might be necessary to have this turned off.
    $SqlQuery = "DECLARE
                    @getValue INT
                ;

                EXEC
                    master..xp_instance_regread
                        @rootkey = N'HKEY_LOCAL_MACHINE',
                        @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
                        @value_name = N'HideInstance',
                        @value = @getValue OUTPUT
                ;

                SELECT
                    @getValue                     AS is_hidden,
                    SERVERPROPERTY('IsClustered') AS is_in_cluster
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the server is hidden (1)." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "If the server is in a cluster it might be necessary to have this turned off." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("is_hidden", "is_in_cluster")
    CsvWriter 'CIS-Hidden-Cluster' "is_hidden,is_in_cluster,expected_is_hidden"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Hidden-Cluster' "$($Row.is_hidden),$($Row.is_in_cluster),1"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.13.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.13.
    # Checks if the default 'sa' account is disabled.
    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.14.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.14.
    # Checks if the default 'sa' account has been renamed.
    $SqlQuery = "SELECT
                    SP.sid         AS SID,
                    SP.name        AS name,
                    SP.is_disabled AS is_disabled
                FROM
                    sys.server_principals AS SP
                WHERE
                    SP.SID = 0x01
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the default 'sa' account is disabled (True)" -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the default 'sa' account has been renamed." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("SID", "name", "is_disabled")
    CsvWriter 'CIS-sa-account' "SID,name,is_disabled"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-sa-account' "$($Row.SID),$($Row.name),$($Row.is_disabled)"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.15.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.15.
    # Checks if the option 'xp_cmdshell' is disabled.
    $SqlQuery = "SELECT name                      AS name,
                        CAST(value AS int)        AS value_configured,
                        CAST(value_in_use AS int) AS value_in_use
                FROM
                    sys.configurations AS C
                WHERE
                    C.name = 'xp_cmdshell'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'xp_cmdshell' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),0"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.16.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.16.
    # Checks if the is_auto_close_on option is turned off for contained databases.
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the 'is_auto_close_on' option is set to 'False' for the databases with 'containment' not set to '0'." -ClosingTag "</p>"
    HTMLPrinter -Table $Script:DatabasesInfo -Columns @("name", "containment", "containment_desc", "is_auto_close_on")
    CsvWriter 'CIS-containment' "name,containment,containment_desc,is_auto_close_on"
    foreach ($Row in $Script:DatabasesInfo) {
        CsvWriter 'CIS-containment' "$($Row.name),$($Row.containment),$($Row.containment_desc),$($Row.is_auto_close_on)"
    }


    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.17.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.17.
    # Checks if no login exists with the name 'sa'.
    $SqlQuery = "SELECT
                    SP.principal_id AS principal_ID,
                    SP.name         AS name,
                    SP.is_disabled  AS is_disabled
                FROM
                    sys.server_principals AS SP
                WHERE
                      SP.type = 'S'
                   OR SP.type = 'U'
                   OR SP.type = 'G'
                ORDER BY
                    SP.principal_ID
                    ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if no login exists with the name 'sa', even if this is not the original 'sa' account." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("principal_ID", "name", "is_disabled")
    CsvWriter 'CIS-sa' "principal_ID,name,is_disabled,expected"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-sa' "$($Row.principal_ID),$($Row.name),$($Row.is_disabled),True"
    }


    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.1.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.1.
    # Checks if the 'Server Authentication' property is set to 'Windows Authentication Mode'.
    $SqlQuery = "SELECT
                    SERVERPROPERTY('IsIntegratedSecurityOnly') AS [login_mode]
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'login_mode' is set to 'Windows Authentication Mode' only (1)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("login_mode")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "login_mode,$($Row.login_mode),,1"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.2.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.2.
    # Checks if the guest user has it's rights revoked on the databases, with the exception of the msdb
    $SqlQuery = "SELECT
                    DB_NAME()            AS database_name,
                    'guest'              AS DB_user,
                    DP.[permission_name] AS permission_name,
                    DP.[state_desc]      AS state_desc
                FROM
                    sys.database_permissions AS DP
                WHERE
                    DP.[grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest')
                ;"
    HTMLPrinter -OpeningTag "<p>" -Content "Check for each of the following databases if the 'CONNECT' permission has been revoked for the 'guest' user." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "The connect permission is required for the 'master', 'tempdb', 'msdb' databases. Therefore they can be ignored." -ClosingTag "</p>"
    CsvWriter 'CIS-CONNECT-permission' "database_name,DB_user,permission_name,state_desc"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:DatabasesInfo) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $Dataset = DataCollector $SqlQuery
            HTMLPrinter -Table $Dataset -Columns @("database_name", "DB_user", "permission_name", "state_desc")
            foreach ($Row in $Dataset) {
                CsvWriter 'CIS-CONNECT-permission' "$($Row.database_name),$($Row.DB_user),$($Row.permission_name),$($Row.state_desc)"
            }
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        HTMLPrinter -Table $Dataset -Columns @("database_name", "DB_user", "permission_name", "state_desc")
        CsvWriter 'CIS-CONNECT-permission' "$($Row.database_name),$($Row.DB_user),$($Row.permission_name),$($Row.state_desc)"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.3
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.3
    # Checks if 'Orphaned Users' are dropped from SQL Server Databases.
    $SqlQuery = "EXEC
                    sp_change_users_login
                        @Action = 'Report'
                ;"
    CsvWriter 'CIS-orphaned-users' "name,UserName,UserSID"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:DatabasesInfo) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $Dataset = DataCollector $SqlQuery
            if ($Dataset.Rows.Count -gt 0) {
                HTMLPrinter -OpeningTag "<p>" -Content "The following accounts in $($db.name) are 'orphaned'." -ClosingTag "</p>"
                HTMLPrinter -OpeningTag "<p>" -Content "These accounts should probably be removed.`n" -ClosingTag "</p>"
                HTMLPrinter -Table $Dataset -Columns @("UserName", "UserSID")
                foreach ($Row in $Dataset) {
                    CsvWriter 'CIS-orphaned-users' "$($db.name),$($Row.UserName),$(ConvertTo-SQLHashString $Row.UserSID)"
                }
            }
            else {
                HTMLPrinter -OpeningTag "<p>" -Content "There are no accounts in $($db.name) that are 'orphaned'.`n" -ClosingTag "</p>"
            }
        }
        $Script:Database = $Script:OriginalDatabase
    }
    else {
        $Dataset = DataCollector $SqlQuery
        if ($Dataset.Rows.Count -gt 0) {
            HTMLPrinter -OpeningTag "<p>" -Content "The following accounts are 'orphaned'." -ClosingTag "</p>"
            HTMLPrinter -OpeningTag "<p>" -Content "These accounts should probably be removed.`n" -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("UserName", "UserSID")
            foreach ($Row in $Dataset) {
                CsvWriter 'CIS-orphaned-users' "$($Script:OriginalDatabase),$($Row.UserName),$(ConvertTo-SQLHashString $Row.UserSID)"
            }
        }
        else {
            HTMLPrinter -OpeningTag "<p>" -Content "There are no accounts that are 'orphaned'.`n" -ClosingTag "</p>"
        }
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.4.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.4.
    # Checks if SQL authentication is not used in contained databases.
    $SqlQuery = "SELECT 
                    DB_NAME()             AS database_name,
                    P.name                AS DB_user,
                    P.authentication_type AS authentication_type
                FROM
                    sys.database_principals AS P
                WHERE
                    P.type IN (
                                'U',
                                'S',
                                'G'
                    )
                ORDER BY
                    authentication_type,
                    DB_user
                ;"
    CsvWriter 'CIS-containment-auth' "database_name,DB_user,authentication_type,not_expected"
    if ($Script:AllDatabases -and $Script:DatabasesInfo.containment -contains 1) {
        foreach ($db in $Script:DatabasesInfo) {
            if ($db.containment -eq 1) {
                $Script:Database = $db.name
                SqlConnectionBuilder
                $Dataset = DataCollector $SqlQuery
                HTMLPrinter -OpeningTag "<p>" -Content "Check if SQL authentication (authentication_type 2) is not used in this contained database." -ClosingTag "</p>"
                HTMLPrinter -Table $Dataset -Columns @("database_name", "DB_user", "authentication_type")
                foreach ($Row in $Dataset) {
                    CsvWriter 'CIS-containment-auth' "$($Row.database_name),$($Row.DB_user),$($Row.authentication_type),2"
                }
            }
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    elseif ($Script:AllDatabases) {
        HTMLPrinter -OpeningTag "<p>" -Content "There are no contained databases." -ClosingTag "</p>"
    } 
    else {
        $contained = $Script:DatabasesInfo | Where-Object name -eq $Database
        if ($contained.containment -eq 1) {
            $Dataset = DataCollector $SqlQuery
            HTMLPrinter -OpeningTag "<p>" -Content "Check if SQL authentication (authentication_type 2) is not used in this contained database." -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("database_name", "DB_user", "authentication_type")
            foreach ($Row in $Dataset) {
                CsvWriter 'CIS-containment-auth' "$($Row.database_name),$($Row.DB_user),$($Row.authentication_type),2"
            }
        }
        else {
            HTMLPrinter -OpeningTag "<p>" -Content "This database is not a contained database." -ClosingTag "</p>"
        }
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.8.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.8.
    # Checks if only the default permissions specified by Microsoft are granted to the public server role.
    $SqlQuery = "SELECT
                    *
                FROM
                    master.sys.server_permissions AS SP
                WHERE
                    SP.grantee_principal_id = SUSER_SID(N'public')
                ORDER BY
                    SP.class,
                    SP.permission_name,
                    SP.state,
                    SP.major_id
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "The 'public' server role has the following permissions." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "These extra permissions apply to every login on the server. Therefore it should only have the default permissions." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "These are:" -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and class_desc = 'SERVER')" -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 2)" -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 3)" -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 4)" -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 5)" -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("class", "class_desc", "major_id", "minor_id", "grantee_principal_id", "grantor_principal_id", "type", "type", "state", "state_desc")
    CsvWriter 'CIS-public-role-permissions' "class,class_desc,major_id,minor_id,grantee_principal_id,grantor_principal_id,type,state,state_desc"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-public-role-permissions' "$($Row.class),$($Row.class_desc),$($Row.major_id),$($Row.minor_id),$($Row.grantee_principal_id),$($Row.grantor_principal_id),$($Row.type),$($Row.state),$($Row.state_desc)"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.9
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.9
    # Checks if the Windows 'BUILTIN' groups are not SQL Logins.
    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.10.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.10.
    # Checks if it is not allowed for 'WINDOWS_GROUP' users to be added to the server.
    $SqlQuery = "SELECT
                    PR.[name]      AS name,
                    PR.[type_desc] AS type_desc
                FROM
                    sys.server_principals AS PR
                ORDER BY
                    name,
                    type_desc
                ;"
    $AltSqlQuery = "SELECT
                        pr.[name]                AS name,
                        pe.[permission_name]    AS permission_name,
                        pe.[state_desc]         AS 
                    FROM 
                        sys.server_principals pr
                    JOIN 
                        sys.server_permissions pe
                    ON 
                        pr.principal_id = pe.grantee_principal_id
                    WHERE 
                        pr.name like 'BUILTIN%'
                        OR (pr.[type_desc] = 'WINDOWS_GROUP'
                        AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%')	
                    ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "The following list contains all server principals." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Check if none of these principals are Windows BUILTIN groups or accounts." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Check if there are no WINDOWS_GROUP users. (type_desc = WINDOWS_GROUP and name contains the MachineName)`n" -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "type_desc")
    CsvWriter 'CIS-server-principals' "name,type_desc"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-server-principals' "$($Row.name),$($Row.type_desc)"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.11.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.11.
    # Checks if the 'public' server role does not have access to the SQL Agent proxies.
    $SqlQuery = "SELECT
                    sp.name AS proxy_name
                FROM
                         dbo.sysproxylogin       AS SPL
                    JOIN sys.database_principals AS DP  ON DP.sid = SPL.sid
                    JOIN sysproxies              AS SP  ON SP.proxy_id = SPL.proxy_id
                WHERE
                    DP.principal_id = USER_ID('public')
                ;"
    $Script:Database = "msdb"
    SqlConnectionBuilder
    $Dataset = DataCollector $SqlQuery
    if ($Dataset.Rows.Count -gt 0) {
        HTMLPrinter -OpeningTag "<p>" -Content "The 'public' serve role has been granted access to the sql agent following proxies." -ClosingTag "</p>"
        HTMLPrinter -OpeningTag "<p>" -Content "These proxies may have higher privilages then the user calling the proxy. Therefore they should be removed.`n" -ClosingTag "</p>"
        HTMLPrinter -Table $Dataset -Columns @("proxy_name")
        CsvWriter 'CIS-server-principals' "proxy_name"
        foreach ($Row in $Dataset) {
            CsvWriter 'CIS-server-principals' "$($Row.proxy_name)"
        }
    }
    else {
        HTMLPrinter -OpeningTag "<p>" -Content "The 'msdb' database's 'public' role has not been granted access to proxies.`n" -ClosingTag "</p>"
    }
    $Script:Database = $Script:OriginalDatabase
    SqlConnectionBuilder
    
    # This check is based on CIS Microsoft SQL Server 2012 benchmark section 4.2.
    # This check is based on CIS Microsoft SQL Server 2016 benchmark section 4.2.
    # Checks if the 'CHECK_EXPIRATION' option is set to 'ON' for all SQL Authenticated Logins with the sysadmin role.
    # Checks if the 'CHECK_EXPIRATION' option is set to 'ON' for all SQL Authenticated Logins who have been granted the control server permission.
    # The second UNION ALL has been added to check users who have been granted the CONTROL SERVER permission through a server role.
    $SqlQuery = "SELECT
                    L.name                  AS name,
                    'sysadmin membership'   AS access_method,
                    L.is_expiration_checked AS is_expiration_checked
                FROM
                    sys.sql_logins AS L
                WHERE
                    IS_SRVROLEMEMBER('sysadmin', name) = 1

                UNION ALL

                SELECT 
                    L.name                  AS name,
                    'CONTROL SERVER'        AS 'access_method',
                    L.is_expiration_checked AS is_expiration_checked
                FROM
                         sys.sql_logins         AS L
                    JOIN sys.server_permissions AS P ON L.principal_id = P.grantee_principal_id
                WHERE P.type   = 'CL'
                  AND P.state IN (
                                    'G',
                                    'W'
                  )

                UNION ALL

                SELECT
                    L.name                   AS name,
                    P.name   + ' membership' AS 'access_method',
                    L.is_expiration_checked  AS is_expiration_checked
                FROM
                         sys.sql_logins          AS L
                    JOIN sys.server_role_members AS R ON L.principal_id = R.member_principal_id
                    JOIN sys.server_principals   AS P ON P.principal_id = R.role_principal_id
                WHERE R.role_principal_id IN (
                                                SELECT
                                                    P.principal_id
                                                FROM
                                                         sys.server_principals  AS P
                                                    JOIN sys.server_permissions AS PE ON p.principal_id = pe.grantee_principal_id
                                                WHERE
                                                      pe.type = 'CL'
                                                  AND p.type  = 'R'
                )
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if SQL Authenticated Logins have the 'CHECK_EXPIRATION' option set to on." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "access_method", "is_expiration_checked")
    CsvWriter 'CIS-CHECK-EXPIRATION' "name,access_method,is_expiration_checked"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-CHECK-EXPIRATION' "$($Row.name),$($Row.access_method),$($Row.is_expiration_checked)"
    }


    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 4.3.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 4.3.
    # Checks if the 'CHECK_POLICY' Option is set to 'True' for all SQL Authenticated Logins.
    $SqlQuery = "SELECT
                    SL.name              AS name,
                    SL.is_disabled       AS is_disabled,
                    SL.is_policy_checked AS is_policy_checked
                FROM
                    sys.sql_logins AS SL
                ORDER BY
                    Is_policy_checked,
                    Is_disabled
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'is_policy_checked' is set to 'True'." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "is_disabled", "is_policy_checked")
    CsvWriter 'CIS-Check-Policy' "name,is_disabled,is_policy_checked"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Check-Policy' "$($Row.name),$($Row.is_disabled),$($Row.is_policy_checked)"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 5.1.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 5.1.
    # Checks if the maximum number of error log files is set greater than or equal to 12.
    $SqlQuery = "DECLARE
                    @NumErrorLogs int
                ;

                EXEC
                    master.sys.xp_instance_regread
                        N'HKEY_LOCAL_MACHINE',
                        N'Software\Microsoft\MSSQLSERVER\MSSQLSERVER',
                        N'NumErrorLogs',
                        @NumErrorLogs OUTPUT
                ;

                SELECT
                    ISNULL(@NumErrorLogs, -1) AS [number_of_log_files]
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the 'NumberOfLogFiles' is 12 or higher." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "If the number is -1, this might mean that the 'Limit the number of error log files before they are recycled' checkmark is not checked." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("number_of_log_files")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "number_of_log_files,$($Row.number_of_log_files),,>12"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 5.2.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 5.2.
    # Checks if the default trace is enabled.
    $SqlQuery = "SELECT name                      AS name,
                        CAST(value AS int)        AS value_configured,
                        CAST(value_in_use AS int) AS value_in_use
                FROM
                    sys.configurations AS C
                WHERE
                    C.name = 'default trace enabled'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'default trace enabled' is enabled (1)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "value_configured", "value_in_use")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.value_configured),$($Row.value_in_use),1"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 5.3.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 5.3.
    # Checks if the 'Login Auditing' is set to 'faled logins'
    $SqlQuery = "EXEC
                    xp_loginconfig 'audit level'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the 'audit level' is configured to failure." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "A value of 'all' is also accepted, however it is recommended to check this with the SQL Server audit feature." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "config_value")
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Compliance' "$($Row.name),$($Row.config_value),,failure"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 5.4.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 5.4.
    # Checks if the 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'.
    $SqlQuery = "SELECT
                    S.name                AS 'audit_name',
                    CASE
                        WHEN S.is_state_enabled = 1
                        THEN 'Y'
                        
                        WHEN S.is_state_enabled = 0
                        THEN 'N'
                    END                   AS 'audit_enabled',
                    S.type_desc           AS 'write_location',
                    SA.name               AS 'audit_speciication_name',
                    CASE SA.is_state_enabled
                        WHEN 1
                        THEN 'Y'
                        
                        WHEN 0
                        THEN 'N'
                    END                   AS 'audit_specification_enabled',
                    SAD.audit_action_name AS audit_action_name,
                    SAD.audited_result    AS audited_result
                FROM
                         sys.server_audit_specification_details AS SAD
                    JOIN sys.server_audit_specifications        AS SA  ON SAD.server_specification_id = SA.server_specification_id
                    JOIN sys.server_audits                      AS S   ON SA.audit_guid               = S.audit_guid
                ORDER BY
                    audit_enabled,
                    audit_name,
                    audit_specification_enabled,
                    audit_action_name
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "3 Rows should be returned." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "For these rows check if both the 'Audit Enabled' and 'Audit Specification Enabled' are set to 'Y'." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Also check if 'audited_result' is set to 'SUCCESS AND FAILURE'." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("audit_name", "audit_enabled", "write_location", "audit_specification_name", "audit_specification_enabled", "audit_action_name", "audited_result")
    CsvWriter 'CIS-Audit-Enabled' "audit_name,audit_enabled,write_location,audit_specification_name,audit_specification_enabled,audit_action_name,audited_result"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Audit-Enabled' "$($Row.audit_name),$($Row.audit_enabled),$($Row.write_location),$($Row.audit_specification_name),$($Row.audit_specification_enabled),$($Row.audit_action_name),$($Row.audited_result)"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 6.2.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 6.2.
    # Checks if user defined CLR assemblies are set to 'SAFE_ACCESS'.
    $SqlQuery = "SELECT
                    A.name                AS name,
                    A.permission_set_desc AS permission_set_desc,
                    A.is_user_defined     AS is_user_defined
                FROM
                    sys.assemblies AS A
                ORDER BY
                    is_user_defined,
                    permission_set_desc
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if all is_user_defined assemblies have 'SAFE_ACCESS' set under 'permission_set_desc'." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "permission_set_desc", "is_user_defined")
    CsvWriter 'CIS-Safe-Access' "name,permission_set_desc,is_user_defined"
    foreach ($Row in $Dataset) {
        CsvWriter 'CIS-Safe-Access' "$($Row.name),$($Row.permission_set_desc),$($Row.is_user_defined)"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 7.1.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 7.1.
    # Checks if 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher.
    $SqlQuery = "SELECT 
                        DB_NAME() AS database_name,
                        SK.*
                FROM
                    sys.symmetric_keys AS SK
                ;"
    HTMLPrinter -OpeningTag "<p>" -Content "Check for every databse if the 'algorithm_desc' is set to 'AES_128', 'AES_192' or 'AES_256'." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "If no output is returned for a database then this means that no symmetric key is available for that database.`n" -ClosingTag "</p>"
    CsvWriter 'CIS-SKE' "database_name,name,principal_id,symmetric_key_id,key_length,key_algorithm,algorithm_desc,create_date,modify_date,key_guid,key_thumbprint,provider_type,cryptographic_provider_guid,cryptographic_provider_algid,RowError,RowState,Table,ItemArray,HasErrors"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:DatabasesInfo) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $Dataset = DataCollector $SqlQuery
            HTMLPrinter -Table $Dataset -Columns @("*")
            foreach ($Row in $Dataset) {
                CsvWriter 'CIS-SKE' "$($Row.database_name),$($Row.name),$($Row.principal_id),$($Row.symmetric_key_id),$($Row.key_length),$($Row.key_algorithm),$($Row.algorithm_desc),$($Row.create_date),$($Row.modify_date),$($Row.key_guid),$($Row.key_thumbprint),$($Row.provider_type),$($Row.cryptographic_provider_guid),$($Row.cryptographic_provider_algid),$($Row.RowError),$($Row.RowState),$($Row.Table),$($Row.ItemArray),$($Row.HasErrors)"
            }
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        HTMLPrinter -Table $Dataset -Columns @("*")
        CsvWriter 'CIS-SKE' "$($database_name),$($name),$($principal_id),$($symmetric_key_id),$($key_length),$($key_algorithm),$($algorithm_desc),$($create_date),$($modify_date),$($key_guid),$($key_thumbprint),$($provider_type),$($cryptographic_provider_guid),$($cryptographic_provider_algid),$($RowError),$($RowState),$($Table),$($ItemArray),$($HasErrors)"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 7.2.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 7.2.
    # Checks if 'Asymmetric Key Size' is set to 'RSA_2048'.
    $SqlQuery = "SELECT
                    DB_NAME()     AS database_name,
                    AK.name       AS key_name,
                    AK.key_length AS key_length
                FROM
                    sys.asymmetric_keys AS AK
                ;"
    HTMLPrinter -OpeningTag "<p>" -Content "Check for every databse if the 'key_length' is set to '2048'." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "If no output is returned for a database then this means that no asymmetric key is available for that database.`n" -ClosingTag "</p>"
    CsvWriter 'CIS-key-length' "database_name,key_name,key_length,expected"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:DatabasesInfo) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $Dataset = DataCollector $SqlQuery
            HTMLPrinter -Table $Dataset -Columns @("database_name", "key_name", "key_length")
            foreach ($Row in $Dataset) {
                CsvWriter 'CIS-key-length' "$($Row.database_name),$($Row.key_name),$($Row.key_length),2048"
            }
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        HTMLPrinter -Table $Dataset -Columns @("database_name", "key_name", "key_length")
        foreach ($Row in $Dataset) {
            CsvWriter 'CIS-key-length' "$($Row.database_name),$($Row.key_name),$($Row.key_length),2048"
        }
    }
}

function UserManagement {
    <#
    .SYNOPSIS
    Checks Usermanagement for the SQL server and it's databases.
    
    .DESCRIPTION
    Usermanagment is checked both on the server level and on the database level.

    First the login to database user mapping is checked.

    Secondly the server level data is gathered.
    This starts with checking for every login to see which roles they possess.
    Then every server non-fixed server role is checked to see which permissions they possess.
    Finally every login is checked again to see which permissions they possess that are granted outside of a role.

    Lastly the same checks from the server level are performed on the database level.
    Depending on the flags the script was started with it will either check all databases or only the specified one.
    
    .EXAMPLE
    UserManagment
    
    .NOTES
    Depending on the amount of users and how their permissions are managed this function may create a lot of data.
    #>

    Write-Host "###### Now checking User Management"
    HTMLPrinter -OpeningTag "<h1 id='User_management' class='headers'>" -Content "User management" -ClosingTag "</h1>"
    HTMLPrinter -OpeningTag "<h3 id='Login_to_user_mapping' class='headers'>" -Content "Login to user mapping" -ClosingTag "</h3>"

    # Setup for the authorization matrix.
    $AuthorizationMatrix = New-Object System.Data.DataTable
    $AuthorizationMatrix.Columns.Add("login_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("server_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("login_type", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_role_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_schema_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_object_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_object_type", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_permission_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_permission_state", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_user_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_role_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_schema_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_object_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_object_type", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_permission_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_permission_state", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("notes", "System.String") | Out-Null
    
    # Step 0: Gather all non server role principal logins (used for the authorization matrix)
    $SqlQuery = "SELECT
                    @@SERVERNAME AS server_name,
                    SP.name      AS login_name,
                    SP.type_desc AS login_type
                FROM
                    sys.server_principals AS SP
                WHERE
                    SP.type != 'R'
                ORDER BY
                    SP.name
                ;"
    $Dataset = DataCollector $SqlQuery
    foreach ($Row in $Dataset) {
        if ($Row.login_name -ne "sa" -and $Row.login_name -notlike "##MS_*" -and $Row.login_name -notlike "NT Service\*" -and $Row.login_name -notlike "NT AUTHORITY\*" ) {
            $new_row = $AuthorizationMatrix.NewRow()

            $new_row.login_name = $Row.login_name
            $new_row.server_name = $Row.server_name
            $new_row.login_type = $Row.login_type
    
            $AuthorizationMatrix.Rows.Add($new_row)
        }
    }

    # Step 1: Maps each login to all it's corresponding database users.
    $SqlQuery = "EXEC
                    sp_MSloginmappings
                ;"
    $Dataset = DataCollector $SqlQuery "y"
    HTMLPrinter -OpeningTag "<p>" -Content "This table contains every login on the server and their corresponding database accounts." -ClosingTag "</p>"
    
    # Because the sp_MSloginMappings sends back multiple tables they need to be joined togheter.
    $TempTable = New-Object System.Data.DataTable
    $TempTable.Columns.Add("LoginName", "System.String") | Out-Null
    $TempTable.Columns.Add("DBName", "System.String") | Out-Null
    $TempTable.Columns.Add("UserName", "System.String") | Out-Null
    $TempTable.Columns.Add("AliasName", "System.String") | Out-Null
    foreach ($DataTable in $Dataset.Tables) {
        foreach ($Row in $DataTable) {
            $TempTable.ImportRow($Row)
        }
    }
    HTMLPrinter -Table $TempTable -Columns @("LoginName", "DBName", "UserName", "AliasName")
    CsvWriter 'UM-UserMapping' "LoginName,DBName,UserName,AliasName"
    foreach ($Row in $TempTable) {
        CsvWriter 'UM-UserMapping' "$($Row.LoginName),$($Row.DBName),$($Row.UserName),$($Row.AliasName)"
    }

    HTMLPrinter -OpeningTag "<h3 id='Logins_permissions' class='headers'>" -Content "Logins permissions" -ClosingTag "</h3>"
    # Step 2: Audit who is in server-level roles.
    $SqlQuery = "SELECT
                    @@SERVERNAME                     AS server_name,
                    SUSER_NAME(RM.role_principal_id) AS server_role,
                    LGN.name                         AS member_name,
                    LGN.type_desc                    AS type_desc,
                    LGN.create_date                  AS date_created,
                    LGN.modify_date                  AS last_modified
                FROM
                               sys.server_role_members AS RM
                    INNER JOIN sys.server_principals   AS LGN ON RM.member_principal_id = LGN.principal_id
                ORDER BY
                    server_role,
                    type_desc
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "A list of who is in server-level roles" -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("server_name", "server_role", "member_name", "type_desc", "date_created", "last_modified")
    CsvWriter 'UM-Server-who-is-level-roles' "server_name,server_role,member_name,type_desc,date_created,last_modified"
    foreach ($Row in $Dataset) {
        CsvWriter 'UM-Server-who-is-level-roles' "$($Row.server_name),$($Row.server_role),$($Row.member_name),$($Row.type_desc),$($Row.date_created),$($Row.last_modified)"
    }
    foreach ($Row in $Dataset) {
        if ($Row.member_name -ne "sa" -and $Row.member_name -notlike "##MS_*" -and $Row.member_name -notlike "NT Service\*" -and $Row.member_name -notlike "NT AUTHORITY\*" ) {
            $new_row = $AuthorizationMatrix.NewRow()

            $new_row.login_name = $Row.member_name
            $new_row.server_name = $Row.server_name
            $new_row.login_type = $Row.type_desc
            $new_row.srv_role_name = $Row.server_role


            $AuthorizationMatrix.Rows.Add($new_row)
        }
    }

    # Step 3: Audit the permissions of non-fixed server-level roles.
    $SqlQuery = "SELECT
                    @@SERVERNAME                        AS server_name,
                    PR.name                             AS role_name,
                    PE.permission_name                  AS permission_name,
                    PE.state_desc                       AS state_desc,
                    SUSER_NAME(PE.grantor_principal_id) AS grantor,
                    PR.create_date                      AS date_created,
                    PR.modify_date                      AS last_modified
                FROM
                         sys.server_principals  AS PR
                    JOIN sys.server_permissions AS PE ON PE.grantee_principal_id = PR.principal_id
                WHERE
                    PR.type = 'R'
                ORDER BY
                    PR.principal_id,
                    state_desc,
                    permission_name;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "A list of Server level roles, defining what they are, and what they can do." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Fixed server roles are not shown." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("server_name", "role_name", "permission_name", "state_desc", "grantor", "date_created", "last_modified")
    CsvWriter 'UM-Server-level-roles' "server_name,role_name,permission_name,state_desc,grantor,date_created,last_modified"
    foreach ($Row in $Dataset) {
        CsvWriter 'UM-Server-level-roles' "$($Row.server_name),$($Row.role_name),$($Row.permission_name),$($Row.state_desc),$($Row.grantor),$($Row.date_created),$($Row.last_modified)"
    }

    # Step 4: Audit any Logins that have access to specific objects outside of a role.
    $SqlQuery = "SELECT
                    @@SERVERNAME                AS server_name,
                    ISNULL(sch.name, osch.name) AS schema_name,
                    ISNULL(o.name, '.')         AS object_name,
                    O.type_desc                 AS type_desc,
                    SPRIN.name                  AS grantee,
                    SPRIN.type_desc             AS login_type,
                    GRANTOR.name                AS grantor,
                    SPRIN.type_desc             AS principal_type_desc,
                    SPER.permission_name        AS permission_name,
                    SPER.state_desc             AS permission_state_desc
                FROM
                                    sys.server_permissions AS SPER
                    INNER JOIN      sys.server_principals  AS SPRIN    ON SPER.grantee_principal_id = SPRIN.principal_id
                    INNER JOIN      sys.server_principals  AS GRANTOR  ON SPER.grantor_principal_id = GRANTOR.principal_id
                    LEFT OUTER JOIN sys.schemas            AS SCH      ON SPER.major_id             = SCH.schema_id
                                                                      AND SPER.class                = 3
                    LEFT OUTER JOIN sys.all_objects        AS O        ON SPER.major_id             = O.OBJECT_ID
                                                                      AND sper.class                = 1
                    LEFT OUTER JOIN sys.schemas            AS OSCH     ON O.schema_id               = OSCH.schema_id
                WHERE
                        sprin.name <> 'public'
                    AND sper.type  <> 'CO'
                    AND sprin.type <> 'R'
                ORDER BY
                    grantee,
                    grantor,
                    permission_state_desc,
                    permission_name
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "A list of permissions directly granted or denied to logins." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("server_name", "schema_name", "object_name", "type_desc", "grantee", "grantor", "principal_type_desc", "permission_name", "permission_state_desc")
    CsvWriter 'UM-permissions-at-login' "server_name,schema_name,object_name,type_desc,grantee,grantor,principal_type_desc,permission_name,permission_state_desc"
    foreach ($Row in $Dataset) {
        CsvWriter 'UM-permissions-at-login' "$($Row.server_name),$($Row.schema_name),$($Row.object_name),$($Row.type_desc),$($Row.grantee),$($Row.grantor),$($Row.principal_type_desc),$($Row.permission_name),$($Row.permission_state_desc)"
    }
    foreach ($Row in $Dataset) {
        if ($Row.grantee -ne "sa" -and $Row.grantee -notlike "##MS_*" -and $Row.grantee -notlike "NT Service\*" -and $Row.grantee -notlike "NT AUTHORITY\*" ) {
            $new_row = $AuthorizationMatrix.NewRow()

            $new_row.login_name = $Row.grantee
            $new_row.server_name = $Row.server_name
            $new_row.login_type = $Row.principal_type_desc
            $new_row.srv_schema_name = $Row.schema_name
            $new_row.srv_object_name = $Row.object_name
            $new_row.srv_object_type = $Row.type_desc
            $new_row.srv_permission_name = $Row.permission_name
            $new_row.srv_permission_state = $Row.permission_state_desc

            $AuthorizationMatrix.Rows.Add($new_row)
        }
    }

    # Step 5: Audit who has access to the database.
    $SqlQueryDBAccess = "SELECT
                    @@SERVERNAME                    AS server_name,
                    DB_NAME()                       AS database_name, 
                    DP.name                         AS user_name,
                    USER_NAME(SM.role_principal_id) AS role_name,
                    SUSER_SNAME(DP.sid)             AS login_name,
                    DP.type_desc                    AS login_type,
                    DP.create_date                  AS date_created,
                    DP.modify_date                  AS last_modified
                FROM
                              sys.database_principals   AS DP
                    LEFT JOIN sys.database_role_members AS SM ON DP.principal_id = SM.member_principal_id
                WHERE
                    DP.type IN (
                        'C',
                        'E',
                        'G',
                        'K',
                        'S',
                        'U',
                        'X'
                    )
                ORDER BY
                    role_name,
                    user_name
                ;"
    
    # Step 6: Audit roles on each database, defining what they are, and what they can do.
    $SqlQueryDBRoles = "SELECT
                    @@SERVERNAME                AS server_name,
                    DB_NAME()                   AS database_name,
                    DPRIN.name                  AS role_name,
                    ISNULL(SCH.name, OSCH.name) AS schema_name,
                    ISNULL(O.name, '.')         AS object_name,
                    DPERM.permission_name       AS permission_name,
                    DPERM.state_desc            AS state_desc,
                    GRANTOR.name                AS grantor,
                    DPRIN.create_date           AS date_created,
                    DPRIN.modify_date           AS last_modified
                FROM                sys.database_permissions AS DPERM
                    INNER JOIN      sys.database_principals  AS DPRIN    ON DPERM.grantee_principal_id = DPRIN.principal_id
                    INNER JOIN      sys.database_principals  AS GRANTOR  ON DPERM.grantor_principal_id = GRANTOR.principal_id
                    LEFT OUTER JOIN sys.schemas              AS SCH      ON DPERM.major_id             = SCH.schema_id
                                                                        AND DPERM.class                = 3
                    LEFT OUTER JOIN sys.all_objects          AS O        ON DPERM.major_id             = O.OBJECT_ID
                                                                        AND DPERM.class                = 1
                    LEFT OUTER JOIN sys.schemas              AS OSCH     ON O.schema_id                = OSCH.schema_id
                WHERE
                        dprin.name <> 'public'
                    AND dperm.type <> 'CO'
                    AND dprin.type =  'R'
                ORDER BY
                    role_name,
                    state_desc,
                    grantor,
                    permission_name
                ;"

    # Step 7: Audit any users that have access to specific objects outside of a role
    $SqlQueryDBRights = "SELECT
                    @@SERVERNAME                AS server_name,
                    DB_NAME()                   AS database_name,
                    ISNULL(SCH.name, OSCH.name) AS schema_name,
                    ISNULL(O.name, '.')         AS object_name,
                    O.type_desc                 AS type_desc,
                    DPRIN.NAME                  AS grantee,
                    SUSER_SNAME(DPRIN.sid)      AS login_name,
                    GRANTOR.name                AS grantor,
                    DPRIN.type_desc             AS principal_type_desc,
                    DPERM.permission_name       AS permission_name,
                    DPERM.state_desc            AS permission_type_desc
                FROM
                               sys.database_permissions AS DPERM
                    INNER JOIN sys.database_principals  AS DPRIN    ON DPERM.grantee_principal_id = DPRIN.principal_id
                    INNER JOIN sys.database_principals  AS GRANTOR  ON DPERM.grantor_principal_id = GRANTOR.principal_id
                    LEFT OUTER JOIN sys.schemas         AS SCH      ON DPERM.major_id             = SCH.schema_id
                                                                   AND DPERM.class                = 3
                    LEFT OUTER JOIN sys.all_objects     AS O        ON DPERM.major_id             = O.OBJECT_ID
                                                                   AND DPERM.class                = 1
                    LEFT OUTER JOIN sys.schemas         AS OSCH     ON O.schema_id                = OSCH.schema_id
                WHERE
                        DPRIN.name <> 'public'
                    AND DPERM.type <> 'CO'
                    AND DPRIN.type <> 'R'
                ORDER BY
                    grantee,
                    grantor,
                    permission_type_desc,
                    permission_name
                ;"

    if ($Script:AllDatabases) {
        HTMLPrinter -OpeningTag "<h3 id='Databases' class='headers'>" -Content "Databases" -ClosingTag "</h3>"
        foreach ($db in $Script:DatabasesInfo) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            HTMLPrinter -OpeningTag "<h3 id='$Script:Database' class='headers'>" -Content $Script:Database -ClosingTag "</h3>"

            $Dataset = DataCollector $SqlQueryDBAccess
            HTMLPrinter -OpeningTag "<p>" -Content "A list of users and the roles they are in." -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("server_name", "database_name", "user_name", "role_name", "login_name", "login_type", "date_created", "last_modified")
            CsvWriter "UM-Users-roles-$($db.name)" "server_name,database_name,user_name,role_name,login_name,login_type,date_created,last_modified"
            foreach ($Row in $Dataset) {
                CsvWriter "UM-Users-roles-$($db.name)" "$($Row.server_name),$($Row.database_name),$($Row.user_name),$($Row.role_name),$($Row.login_name),$($Row.login_type),$($Row.date_created),$($Row.last_modified)"
            }
            foreach ($Row in $Dataset) {
                if ($Row.user_name -ne "guest" -and $Row.user_name -ne "INFORMATION_SCHEMA" -and $Row.user_name -ne "MS_DataCollectorInternalUser" -and $Row.user_name -ne "sys" -and $Row.login_name -ne "sa" -and $Row.login_name -notlike "##MS_*" -and $Row.login_name -notlike "NT Service\*" -and $Row.login_name -notlike "NT AUTHORITY\*") {
                    $new_row = $AuthorizationMatrix.NewRow()
        
                    $new_row.login_name = $Row.login_name
                    $new_row.server_name = $Row.server_name
                    $new_row.login_type = $Row.login_type
                    $new_row.db_name = $Row.database_name
                    $new_row.db_user_name = $Row.user_name
                    $new_row.db_role_name = $Row.role_name
        
                    $AuthorizationMatrix.Rows.Add($new_row)
                }
            }

            if ($Dataset.Tables.Count -ne 0) {
                $Dataset = DataCollector $SqlQueryDBRoles
                HTMLPrinter -OpeningTag "<p>" -Content "A list of Database level roles, defining what they are, and what they can do." -ClosingTag "</p>"
                HTMLPrinter -OpeningTag "<p>" -Content "Fixed database roles are not shown." -ClosingTag "</p>"
                HTMLPrinter -Table $Dataset -Columns @("server_name", "database_name", "role_name", "schema_name", "object_name", "permission_name", "state_desc", "grantor", "date_created", "last_modified")
                CsvWriter "UM-database-level-roles-$($db.name)" "server_name,database_name,role_name,schema_name,object_name,permission_name,state_desc,grantor,date_created,last_modified"
                foreach ($Row in $Dataset) {
                    CsvWriter "UM-database-level-roles-$($db.name)" "$($Row.server_name),$($Row.database_name),$($Row.role_name),$($Row.schema_name),$($Row.object_name),$($Row.permission_name),$($Row.state_desc),$($Row.grantor),$($Row.date_created),$($Row.last_modified)"
                }
            }

            if ($Dataset.Tables.Count -ne 0) {
                $Dataset = DataCollector $SqlQueryDBRights
                HTMLPrinter -OpeningTag "<p>" -Content "Audit any users that have access to specific objects outside of a role" -ClosingTag "</p>"
                HTMLPrinter -Table $Dataset -Columns @("server_name", "database_name", "schema_name", "object_name", "type_desc", "grantee", "login_name", "grantor", "principal_type_desc", "permission_name", "permission_type_desc")    
                CsvWriter "UM-user-specific-objects-$($db.name)" "server_name,database_name,schema_name,object_name,type_desc,grantee,login_name,login_name,principal_type_desc,permission_name,permission_type_desc"
                foreach ($Row in $Dataset) {
                    CsvWriter "UM-user-specific-objects-$($db.name)" "$($Row.server_name),$($Row.database_name),$($Row.schema_name),$($Row.object_name),$($Row.type_desc),$($Row.grantee),$($Row.login_name),$($Row.login_name),$($Row.principal_type_desc),$($Row.permission_name),$($Row.permission_type_desc)"
                }
                foreach ($Row in $Dataset) {
                    if ($Row.user_name -ne "guest" -and $Row.user_name -ne "INFORMATION_SCHEMA" -and $Row.user_name -ne "MS_DataCollectorInternalUser" -and $Row.user_name -ne "sys" -and $Row.login_name -ne "sa" -and $Row.login_name -notlike "##MS_*" -and $Row.login_name -notlike "NT Service\*" -and $Row.login_name -notlike "NT AUTHORITY\*") {
                        $new_row = $AuthorizationMatrix.NewRow()

                        $new_row.login_name = $Row.login_name
                        $new_row.server_name = $Row.server_name
                        $new_row.login_type = $Row.principal_type_desc
                        $new_row.db_name = $Row.database_name
                        $new_row.db_user_name = $Row.grantee
                        $new_row.db_schema_name = $Row.schema_name
                        $new_row.db_object_name = $Row.object_name
                        $new_row.db_object_type = $Row.type_desc
                        $new_row.db_permission_name = $Row.permission_name
                        $new_row.db_permission_state = $Row.permission_state_desc

                        $AuthorizationMatrix.Rows.Add($new_row)
                    }
                }
            }
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        HTMLPrinter -OpeningTag "<h3 id='$Script:Database' class='headers'>" -Content $Script:Database -ClosingTag "</h3>"
        $Dataset = DataCollector $SqlQueryDBAccess
        HTMLPrinter -OpeningTag "<p>" -Content "A list of users and the roles they are in." -ClosingTag "</p>"
        HTMLPrinter -Table $Dataset -Columns @("server_name", "database_name", "user_name", "role_name", "login_name", "login_type", "date_created", "last_modified")
        CsvWriter "UM-Users-roles-$($Script:Database)" "server_name,database_name,role_name,schema_name,login_name,login_type,date_created,last_modified"
        foreach ($Row in $Dataset) {
            CsvWriter "UM-Users-roles-$($Script:Database)" "$($Row.server_name),$($Row.database_name),$($Row.role_name),$($Row.schema_name),$($Row.login_name),$($Row.login_type),$($Row.date_created),$($Row.last_modified)"
        }
        foreach ($Row in $Dataset) {
            if ($Row.user_name -ne "guest" -and $Row.user_name -ne "INFORMATION_SCHEMA" -and $Row.user_name -ne "MS_DataCollectorInternalUser" -and $Row.user_name -ne "sys" -and $Row.login_name -ne "sa" -and $Row.login_name -notlike "##MS_*" -and $Row.login_name -notlike "NT Service\*" -and $Row.login_name -notlike "NT AUTHORITY\*") {
                $new_row = $AuthorizationMatrix.NewRow()

                $new_row.login_name = $Row.login_name
                $new_row.server_name = $Row.server_name
                $new_row.login_type = $Row.login_type
                $new_row.db_name = $Row.database_name
                $new_row.db_user_name = $Row.user_name
                $new_row.db_role_name = $Row.role_name

                $AuthorizationMatrix.Rows.Add($new_row)
            }
        }

        if ($Dataset.Tables.Count -ne 0) {
            $Dataset = DataCollector $SqlQueryDBRoles
            HTMLPrinter -OpeningTag "<p>" -Content "A list of Database level roles, defining what they are, and what they can do." -ClosingTag "</p>"
            HTMLPrinter -OpeningTag "<p>" -Content "Fixed database roles are not shown." -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("server_name", "database_name", "role_name", "schema_name", "object_name", "permission_name", "state_desc", "grantor", "date_created", "last_modified")    
            CsvWriter "UM-database-level-roles-$($Script:Database)" "server_name,database_name,role_name,schema_name,object_name,permission_name,state_desc,grantor,date_created,last_modified"
            foreach ($Row in $Dataset) {
                CsvWriter "UM-database-level-roles-$($Script:Database)" "$($Row.server_name),$($Row.database_name),$($Row.role_name),$($Row.schema_name),$($Row.object_name),$($Row.permission_name),$($Row.state_desc),$($Row.grantor),$($Row.date_created),$($Row.last_modified)"
            }
        }

        $Dataset = DataCollector $SqlQueryDBRights
        if ($Dataset.Tables.Count -ne 0) {
            HTMLPrinter -OpeningTag "<p>" -Content "Audit any users that have access to specific objects outside of a role" -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("server_name", "database_name", "schema_name", "object_name", "type_desc", "grantee", "login_name", "grantor", "principal_type_desc", "permission_name", "permission_type_desc")
            CsvWriter "UM-user-specific-objects-$($Script:Database)" "server_name,database_name,schema_name,object_name,type_desc,grantee,login_name,login_name,principal_type_desc,permission_name,permission_type_desc"
            foreach ($Row in $Dataset) {
                CsvWriter "UM-user-specific-objects-$($Script:Database)" "$($Row.server_name),$($Row.database_name),$($Row.schema_name),$($Row.object_name),$($Row.type_desc),$($Row.grantee),$($Row.login_name),$($Row.login_name),$($Row.principal_type_desc),$($Row.permission_name),$($Row.permission_type_desc)"
            }
            foreach ($Row in $Dataset) {
                if ($Row.user_name -ne "guest" -and $Row.user_name -ne "INFORMATION_SCHEMA" -and $Row.user_name -ne "MS_DataCollectorInternalUser" -and $Row.user_name -ne "sys" -and $Row.login_name -ne "sa" -and $Row.login_name -notlike "##MS_*" -and $Row.login_name -notlike "NT Service\*" -and $Row.login_name -notlike "NT AUTHORITY\*") {
                    $new_row = $AuthorizationMatrix.NewRow()

                    $new_row.login_name = $Row.login_name
                    $new_row.server_name = $Row.server_name
                    $new_row.login_type = $Row.principal_type_desc
                    $new_row.db_name = $Row.database_name
                    $new_row.db_user_name = $Row.grantee
                    $new_row.db_schema_name = $Row.schema_name
                    $new_row.db_object_name = $Row.object_name
                    $new_row.db_object_type = $Row.type_desc
                    $new_row.db_permission_name = $Row.permission_name
                    $new_row.db_permission_state = $Row.permission_state_desc

                    $AuthorizationMatrix.Rows.Add($new_row)
                }
            }
        }
    }

    HTMLPrinter -OpeningTag "<h3 id='with-grant' class='headers'>" -Content 'with grant permission' -ClosingTag "</h3>"
    # Grab all users with 'with grant's.
    $SqlQuery = "SELECT 
                    DB_NAME()           AS db_name, 
                    PM.class_desc       AS class_desc,
                    P.name              AS grantee,
                    O.name              AS grantor,
                    PM.type             AS type,
                    PM.permission_name  AS permission_name,
                    PM.state            AS state
                FROM (
                    SELECT 
                        * 
                    FROM 
                        sys.database_permissions
                    UNION ALL
                    SELECT 
                        * 
                    FROM 
                        sys.server_permissions 
                ) AS PM 
                JOIN sys.server_principals AS P 
                    ON PM.grantee_principal_id = P.principal_id
                JOIN sys.server_principals AS O 
                    ON PM.grantor_principal_id = O.principal_id
                WHERE 
                    state not like 'G'
                ;"
    CsvWriter 'UM-users-with-with-grant' "db_name,class_desc,grantee,grantor,type,permission_name,state"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:DatabasesInfo) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $Dataset = DataCollector $SqlQuery
            if ($Dataset.Rows.Count -gt 0) {
                HTMLPrinter -OpeningTag "<p>" -Content "The following users in $($db.name) have 'with grant'." -ClosingTag "</p>"
                HTMLPrinter -Table $Dataset -Columns @("db_name","class_desc","grantee","grantor","type","permission_name","state")
                foreach ($Row in $Dataset) {
                    CsvWriter 'UM-users-with-with-grant' "$($db.name),$($Row.class_desc),$($Row.grantee),$($Row.grantor),$($Row.type),$($Row.permission_name),$($Row.state)"
                }
            }
            else {
                HTMLPrinter -OpeningTag "<p>" -Content "There are no accounts with 'with grant' rights." -ClosingTag "</p>"
            }
        }
        $Script:Database = $Script:OriginalDatabase
    }
    else {
        $Dataset = DataCollector $SqlQuery
        if ($Dataset.Rows.Count -gt 0) {
            HTMLPrinter -OpeningTag "<p>" -Content "The following users in $($db.name) have 'with grant'." -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("db_name","class_desc","grantee","grantor","type","permission_name","state")
            foreach ($Row in $Dataset) {
                CsvWriter 'UM-users-with-with-grant' "$($db.name),$($Row.class_desc),$($Row.grantee),$($Row.grantor),$($Row.type),$($Row.permission_name),$($Row.state)"
            }
        }
        else {
            HTMLPrinter -OpeningTag "<p>" -Content "There are no accounts with 'with grant' rights." -ClosingTag "</p>"
        }
    }


    $dv = New-Object System.Data.DataView
    $dv = $AuthorizationMatrix.DefaultView;
    $dv.Sort = "login_name, server_name, db_name, db_role_name, db_schema_name, db_object_type, db_object_name, db_permission_state, db_permission_name, srv_role_name, srv_schema_name, srv_object_type, srv_object_name, srv_permission_state, srv_permission_name";
    $AuthorizationMatrix = $dv.ToTable();

    HTMLPrinter -OpeningTag "<h1 id='Authorizationmatrix' class='headers'>" -Content "Authorizationmatrix" -ClosingTag "</h1>"
    HTMLPrinter -Table $AuthorizationMatrix -Columns @(
        "login_name",
        "server_name",
        "login_type",
        "srv_role_name",
        "srv_schema_name",
        "srv_object_name",
        "srv_object_type",
        "srv_permission_name",
        "srv_permission_state",
        "db_name",
        "db_user_name",
        "db_role_name",
        "db_schema_name",
        "db_object_name",
        "db_object_type",
        "db_permission_name",
        "db_permission_state",
        "notes"
    )
    CsvWriter "UM-Authorizationmatrix" "login_name,server_name,login_type,srv_role_name,srv_schema_name,srv_object_name,srv_object_type,srv_permission_name,srv_permission_state,db_name,db_user_name,db_role_name,db_schema_name,db_object_name,db_object_type,db_permission_name,db_permission_state,notes"
    foreach ($Row in $AuthorizationMatrix) {
        CsvWriter "UM-Authorizationmatrix" "$($Row.login_name),$($Row.server_name),$($Row.login_type),$($Row.srv_role_name),$($Row.srv_schema_name),$($Row.srv_object_name),$($Row.srv_object_type),$($Row.srv_permission_name),$($Row.srv_permission_state),$($Row.db_name),$($Row.db_user_name),$($Row.db_role_name),$($Row.db_schema_name),$($Row.db_object_name),$($Row.db_object_type),$($Row.db_permission_name),$($Row.db_permission_state),$($Row.notes)"
    }
}

function HTMLPrinter {
    <#
    .SYNOPSIS
    Converts the gathered data to HTML and sends it to the output file.
    
    .DESCRIPTION
    The HTMLPrinter will take the parameters that are sent and use them to format the gathered data to HTML.
    The formatted HTML will then be sent to the output file.
    There are two sets of parameters that can be used with this method.
    The first set can be used to print headers, text and the likes.
    The second set can be used to print tables.

    .PARAMETER OpeningTag
    The HTML opening tag.

    .PARAMETER Content
    The content to be converted to HTML.

    .PARAMETER ClosingTag
    The HTML closing tag.

    .PARAMETER Table
    The DataTable to be converted to HTML.

    .PARAMETER Columns
    The columns of the DataTable.

    .EXAMPLE
    HTMLPrinter -OpeningTag "<p>" -Content "Example content" -ClosingTag "</p>"

    .EXAMPLE
    HTMLPrinter -Table $Dataset -Columns @("Column1", "Column2", "Column3")
    #>
    [CmdletBinding()]

    param (
        # The HTML opening tag.
        [parameter(ParameterSetName = "Content", Mandatory = $true)]
        [string]
        $OpeningTag,

        # The content to be converted to HTML.
        [parameter(ParameterSetName = "Content", Mandatory = $true)]
        [string]
        $Content,

        # The HTML closing tag.
        [parameter(ParameterSetName = "Content", Mandatory = $true)]
        [string]
        $ClosingTag,

        # The DataTable to be converted to HTML.
        [parameter(ParameterSetName = "Table", Mandatory = $true)]  
        [System.Data.DataTable]
        $Table,

        # The columns of the DataTable.
        [parameter(ParameterSetName = "Table", Mandatory = $true)]
        [array]
        $Columns,

        # Indicates the start of the HTML file.
        [parameter(ParameterSetName = "HTMLStart", Mandatory = $true)]
        [switch]
        $HTMLStart,
        
        # Indicates the end of the HTML file.
        [parameter(ParameterSetName = "HTMLEnd", Mandatory = $true)]
        [switch]
        $HTMLEnd
    )

    $startHTML = @"
<!DOCTYPE html>
<html>

<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
    body, html{
        /* To make use of full height of page*/
        margin: 0;
        padding: 0;
    }
    
    
            .collapsible {
                background-color: #777;
                color: white;
                cursor: pointer;
                padding: 18px;
                width: 20%;
                border: none;
                text-align: left;
                outline: none;
                font-size: 15px;
            }
    
            .active,
            .collapsible:hover {
                background-color: #555;
            }
    
            .content {
                padding: 0 18px;
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.2s ease-out;
                background-color: #f1f1f1;
                overflow-x: auto
            }
    
            TABLE {
                border-width: 1px;
                border-style: solid;
                border-color: black;
                border-collapse: collapse;
                margin-bottom: 20px;
            }
    
            TH {
                border-width: 1px;
                padding: 3px;
                border-style: solid;
                border-color: black;
                background-color: #6495ED;
            }
    
            TD {
                border-width: 1px;
                padding: 3px;
                border-style: solid;
                border-color: black;
            }
    
            .odd {
                background-color: #ffffff;
            }
    
            .even {
                background-color: #dddddd;
            }
            .collapsible:after {
                content: '\02795'; /* Unicode character for "plus" sign (+) */
                font-size: 13px;
                color: white;
                float: right;
                margin-left: 5px;
              }
              
              .active:after {
                content: "\2796"; /* Unicode character for "minus" sign (-) */
              }
    
              .fixed {
                position: fixed;
                overflow-y: scroll;
                max-width: 20%;
                max-height: 100%;
            }
    
            .auditedResults {
                margin-left: 20%;
            }
    
            #Basic_information {
                margin-top: 0;
            }
            #OTP {
                margin-top: 0;
            }
    </style>
</head>

<body>

<div class="content fixed" id='ToC2'>
<nav role='navigation' id='ToC'>

</nav>
</div>
<div class="auditedResults">
"@

    $endHTML = @"
    </div>
    <script>
    var ToC = "<h2 id='OTP'>On this page:</h2>";

    var headers = document.getElementsByClassName("headers");
    for (i = 0; i < headers.length; i++) {
        var current = headers[i];
        console.log(current);

        title = current.textContent;
        console.log(title);
        var type = current.tagName;
        console.log(type);
        link = "#" + current.getAttribute("id");
        console.log(link)

    
        var newLine
    
        if (type == 'H1') {
            newLine =
            "<ul>" +
            "<li>" +
              "<a href='" + link + "'>" +
                title +
              "</a>" +
            "</li>" +
            "</ul>";
        }
        if (type == 'H3') {
            newLine =
            "<ul style='padding-left: 60px;'>" +
            "<li>" +
              "<a href='" + link + "'>" +
                title +
              "</a>" +
            "</li>" +
            "</ul>";
        }
    
        ToC += newLine;
        }

      document.getElementById('ToC').innerHTML = ToC



      var coll = document.getElementsByClassName("collapsible");
      var i;
      
      for (i = 0; i < coll.length; i++) {
        coll[i].addEventListener("click", function() {
          this.classList.toggle("active");
          var content = this.nextElementSibling;
          if (content.style.maxHeight){
            content.style.maxHeight = null;
          } else {
            content.style.maxHeight = content.scrollHeight + "px";
          } 
        });
      }
</script>
    
</body>

</html>
"@

    $CollapsableStart = @"
    <button class="collapsible">Open Table</button>
    <div class="content">
"@

    try {   
        if ($null -ne $Table) {
            Out-File -FilePath $Script:Outfile -InputObject $CollapsableStart -append
            out-file -filepath $Script:Outfile -inputobject ($Table | ConvertTo-Html -Property $Columns -Fragment) -append
            Out-File -FilePath $Script:Outfile -InputObject "</div>" -append
        }
        elseif ($Content -ne "") {
            out-file -filepath $Script:Outfile -InputObject $OpeningTag, $Content, $ClosingTag -append
        }
        elseif ($HTMLStart) {
            out-file -filepath $Script:Outfile -InputObject $startHTML -Append
        }
        elseif ($HTMLEnd) {
            out-file -filepath $Script:Outfile -InputObject $endHTML -Append
        }
    }
    catch {
        Write-Host "An Error has occured."
    }
}

Startup
