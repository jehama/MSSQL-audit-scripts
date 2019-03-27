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
Valid options are: 'All','CIS','UserManagement'.

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
    # This parameter is optional. If it is not used every section will be ran.
    [parameter(ParameterSetName = "WindowsAuthentication")]
    [parameter(ParameterSetName = "SQLAuthentication")]
    [ValidateSet('All', 'CIS', 'UserManagement')]
    [String[]]
    $Include = 'All'
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
    if($SQLAuthentication) {
        $SecurePassword = Read-Host -AsSecureString "Enter password"
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $Script:Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }

    #Sets the output file. If the file already exists the user is prompted to override it or stop the script.
    $Script:Outfile = "audit-MSSQL-" + $Script:Server + ".html"
    if (Test-Path -Path $Script:Outfile) {
        Write-Host "The output file already exists, would you like to overwrite it?"
        Remove-Item $Script:Outfile -Confirm
        if (Test-Path -Path $Script:Outfile) {
            Write-Host "Please move the output file: $Script:Outfile"
            exit
        }
    }

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

    HTMLPrinter -OpeningTag "<h1>" -Content "Basic information" -ClosingTag "</h1>"
    HTMLPrinter -OpeningTag "<p>" -Content "Using $Script:Server as target server." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Using $Script:Database as target database." -ClosingTag "</p>"

    $Script:OriginalDatabase = $Script:Database

    SqlConnectionBuilder    

    CheckFullVersion
    GenerateDatabasesInfo

    Write-Host "Setup completed in:                                  " $Script:Stopwatch.Elapsed
    $Script:TotalTime += $Script:Stopwatch.Elapsed
    Write-Host "Total time elapsed:                                  " $Script:TotalTime
    $Script:Stopwatch.Restart()

    Main
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
        # Each function called corresponds to a different standard.
        L1.1
        L1.2
        L1.3
        L2.1
        L2.2
        L2.8
        L3.3
        L3.4
        L3.5
        L3.7

        Write-Host "CIS Microsoft SQL Server 2016 benchmark completed in:" $Script:Stopwatch.Elapsed
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

    $Script:TotalTime += $Script:Stopwatch.Elapsed
    Write-Host "Audit has finished, total time elapsed:              " $Script:TotalTime
}

function SqlConnectionBuilder {
    <#
    .SYNOPSIS
    Builds and returns the SqlConnection object.
    
    .DESCRIPTION
    Creates an ConnectionString based on the global script variables $Script:Server and $Script:Database.
    
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


    if($AllTables -eq "y")
    {
        ,$Dataset
    }
    else {
        $DataTable = New-Object System.Data.DataTable
        $DataTable = $Dataset.Tables[0]

        ,$DataTable
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
                    @@VERSION AS Version
                ;"
    $Dataset = DataCollector $SqlQuery

    HTMLPrinter -OpeningTag "<h3>" -Content "Server version:" -ClosingTag "</h3>"
    HTMLPrinter -Table $Dataset -Columns @("Version")
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
    $Script:DatabasesInfo.Columns.Add("NumberOfUsers", "System.String") | Out-Null

    $SqlQuery = "SELECT
                    COUNT(*) AS Users
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
        $db.NumberOfUsers = $Dataset.Users
    }
    $Script:Database = $Script:OriginalDatabase
    SqlConnectionBuilder

    HTMLPrinter -OpeningTag "<h3>" -Content "This server contains the following databases:" -ClosingTag "</h3>"
    HTMLPrinter -Table $Script:DatabasesInfo -Columns @("Name", "Create_Date", "NumberOfUsers")
}

function L1.1 {
    <#
    .SYNOPSIS
    Checks control L1.1
    
    .DESCRIPTION
    Checks CIS Microsoft SQL Server 2012 benchmark section 4.2

    Checks CIS Microsoft SQL Server 2016 benchmark section 4.2
    
    .EXAMPLE
    L1.1
    
    .NOTES
    Control L1.1 checks if passwords are periodically changed.
    #>
    [CmdletBinding()]

    param()

    Write-Host "###### Now checking Control L1.1"
    HTMLPrinter -OpeningTag "<h3>" -Content "Control L1.1" -ClosingTag "</h3>"

    # This check is based on CIS Microsoft SQL Server 2012 benchmark section 4.2.
    # This check is based on CIS Microsoft SQL Server 2016 benchmark section 4.2.
    # Checks if the 'CHECK_EXPIRATION' option is set to 'ON' for all SQL Authenticated Logins with the sysadmin role.
    # Checks if the 'CHECK_EXPIRATION' option is set to 'ON' for all SQL Authenticated Logins who have been granted the control server permission.
    # The second UNION ALL has been added to check users who have been granted the CONTROL SERVER permission through a server role.
    $SqlQuery = "SELECT
                    L.name                  AS Name,
                    'sysadmin membership'   AS Access_Method,
                    L.is_expiration_checked AS Is_Expiration_checked
                FROM
                    sys.sql_logins AS L
                WHERE
                    IS_SRVROLEMEMBER('sysadmin', name) = 1

                UNION ALL

                SELECT 
                    L.name                  AS Name,
                    'CONTROL SERVER'        AS 'Access_Method',
                    L.is_expiration_checked AS Is_Expiration_checked
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
                    L.name                   AS Name,
                    P.name   + ' membership' AS 'Access_Method',
                    L.is_expiration_checked  AS Is_Expiration_checked
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
    HTMLPrinter -Table $Dataset -Columns @("Name", "Access_Method", "Is_Expiration_checked")
}

function L1.2 {
    <#
    .SYNOPSIS
    Checks control L1.2
    
    .DESCRIPTION
    Checks CIS Microsoft SQL Server 2012 benchmark section 3.4
    Checks CIS Microsoft SQL Server 2012 benchmark section 4.3

    Checks CIS Microsoft SQL Server 2016 benchmark section 3.4
    Checks CIS Microsoft SQL Server 2016 benchmark section 4.3
    
    .EXAMPLE
    L1.2
    
    .NOTES
    Control L1.2 checks if password strength is adequately enough.
    #>
    [CmdletBinding()]

    param()

    Write-Host "###### Now checking Control L1.2"
    HTMLPrinter -OpeningTag "<h3>" -Content "Control L1.2" -ClosingTag "</h3>"

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.4.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.4.
    # Checks if SQL authentication is not used in contained databases.
    $SqlQuery = "SELECT 
                    DB_NAME()             AS DatabaseName,
                    P.name                AS DBUser,
                    P.authentication_type AS Authentication_type
                FROM
                    sys.database_principals AS P
                WHERE
                    P.type IN (
                                'U',
                                'S',
                                'G'
                    )
                ORDER BY
                    Authentication_type,
                    DBUser
                ;"
    if ($Script:AllDatabases -and $Script:DatabasesInfo.containment -contains 1) {
        foreach ($db in $Script:DatabasesInfo) {
            if($db.containment -eq 1){
                $Script:Database = $db.name
                SqlConnectionBuilder
                $Dataset = DataCollector $SqlQuery
                HTMLPrinter -OpeningTag "<p>" -Content "Check if SQL authentication (authentication_type 2) is not used in this contained database." -ClosingTag "</p>"
                HTMLPrinter -Table $Dataset -Columns @("DatabaseName", "DBUser", "Authentication_Type")
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
        if($contained.containment -eq 1){
            $Dataset = DataCollector $SqlQuery
            HTMLPrinter -OpeningTag "<p>" -Content "Check if SQL authentication (authentication_type 2) is not used in this contained database." -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("DatabaseName", "DBUser", "Authentication_Type")
        }
        else {
            HTMLPrinter -OpeningTag "<p>" -Content "This database is not a contained database." -ClosingTag "</p>"
        }
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 4.3.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 4.3.
    # Checks if the 'CHECK_POLICY' Option is set to 'True' for all SQL Authenticated Logins.
    $SqlQuery = "SELECT
                    SL.name              AS Name,
                    SL.is_disabled       AS Is_Disabled,
                    SL.is_policy_checked AS Is_Policy_Checked
                FROM
                    sys.sql_logins AS SL
                ORDER BY
                    Is_Policy_checked,
                    Is_Disabled
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'is_policy_checked' is set to 'True'." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Is_Disabled", "Is_Policy_Checked")
}

function L1.3 {
    <#
    .SYNOPSIS
    Checks control L1.3
    
    .DESCRIPTION
    Checks CIS Microsoft SQL Server 2012 benchmark section 3.1

    Checks CIS Microsoft SQL Server 2016 benchmark section 3.1
    
    .EXAMPLE
    L1.3
    
    .NOTES
    Control L1.3 checks if two-factor authentication is used with untrusted zones.
    #>
    [CmdletBinding()]

    param()

    Write-Host "###### Now checking Control L1.3"
    HTMLPrinter -OpeningTag "<h3>" -Content "Control L1.3" -ClosingTag "</h3>"

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.1.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.1.
    # Checks if the 'Server Authentication' property is set to 'Windows Authentication Mode'.
    $SqlQuery = "SELECT
                    SERVERPROPERTY('IsIntegratedSecurityOnly') AS [Login_Mode]
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'login_mode' is set to 'Windows Authentication Mode' only (1)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Login_Mode")
}

function L2.1 {
    <#
    .SYNOPSIS
    Checks control L2.1
    
    .DESCRIPTION
    Checks CIS Microsoft SQL Server 2012 benchmark section 3.8
    Checks CIS Microsoft SQL Server 2012 benchmark section 3.11

    Checks CIS Microsoft SQL Server 2016 benchmark section 3.8
    Checks CIS Microsoft SQL Server 2016 benchmark section 3.11

    .EXAMPLE
    L2.1
    
    .NOTES
    Control 2.1 Checks if accounts only have the necessary access rights.
    #>
    [CmdletBinding()]

    param()

    Write-Host "###### Now checking Control L2.1"
    HTMLPrinter -OpeningTag "<h3>" -Content "Control L2.1" -ClosingTag "</h3>"
    
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
    HTMLPrinter -Table $Dataset -Columns @("class", "class_desc", "major_id", "minor_id", "grantee_principal_id", "grantor_principal_id", "type", "permission_name", "state", "state_desc")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.11.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.11.
    # Checks if the 'public' server role does not have access to the SQL Agent proxies.
    $SqlQuery = "SELECT
                    sp.name AS ProxyName
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
        HTMLPrinter -Table $Dataset -Columns @("ProxyName")
    }
    else {
        HTMLPrinter -OpeningTag "<p>" -Content "The 'msdb' database's 'public' role has not been granted access to proxies.`n" -ClosingTag "</p>"
    }
    $Script:Database = $Script:OriginalDatabase
    SqlConnectionBuilder
}

function L2.2 {
    <#
    .SYNOPSIS
    Checks control L2.2
    
    .DESCRIPTION
    Checks CIS Microsoft SQL Server 2012 benchmark section 3.9
    Checks CIS Microsoft SQL Server 2012 benchmark section 3.10

    Checks CIS Microsoft SQL Server 2016 benchmark section 3.9
    Checks CIS Microsoft SQL Server 2016 benchmark section 3.10
    
    .EXAMPLE
    L2.2
    
    .NOTES
    Control 2.2 Checks if accounts  and access rights are authorized.
    #>
    [CmdletBinding()]

    param()

    Write-Host "###### Now checking Control L2.2"
    HTMLPrinter -OpeningTag "<h3>" -Content "Control L2.2" -ClosingTag "</h3>"
    
    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.9
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.9
    # Checks if the Windows 'BUILTIN' groups are not SQL Logins.
    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.10.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.10.
    # Checks if it is not allowed for 'WINDOWS_GROUP' users to be added to the server.
    $SqlQuery = "SELECT
                    PR.[name]      AS Name,
                    PR.[type_desc] AS Type_Desc
                FROM
                    sys.server_principals AS PR
                ORDER BY
                    Name,
                    Type_Desc
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "The following list contains all server principals." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Check if none of these principals are Windows BUILTIN groups or accounts." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Check if there are no WINDOWS_GROUP users. (type_desc = WINDOWS_GROUP and name contains the MachineName)`n" -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Type_Desc")
}

function L2.8 {
    <#
    .SYNOPSIS
    Checks control L2.8
    
    .DESCRIPTION
    Checks CIS Microsoft SQL Server 2012 benchmark section 3.3

    Checks CIS Microsoft SQL Server 2016 benchmark section 3.3
    
    .EXAMPLE
    L2.8
    
    .NOTES
    Control 2.8 Checks if useraccounts and administratoraccounts are periodically evaluated.
    #>
    [CmdletBinding()]

    param()

    Write-Host "###### Now checking Control L2.8"
    HTMLPrinter -OpeningTag "<h3>" -Content "Control L2.8" -ClosingTag "</h3>"
    
    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.3
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.3
    # Checks if 'Orphaned Users' are dropped from SQL Server Databases.
    $SqlQuery = "EXEC
                    sp_change_users_login
                        @Action = 'Report'
                ;"
    $Dataset = DataCollector $SqlQuery
    if ($Dataset.Rows.Count -gt 0) {
        HTMLPrinter -OpeningTag "<p>" -Content "The following accounts are 'orphaned'." -ClosingTag "</p>"
        HTMLPrinter -OpeningTag "<p>" -Content "These accounts should probably be removed.`n" -ClosingTag "</p>"
        HTMLPrinter -Table $Dataset -Columns @("UserName", "UserSID")
    }
    else {
        HTMLPrinter -OpeningTag "<p>" -Content "There are no accounts that are 'orphaned'.`n" -ClosingTag "</p>"
    }
}

function L3.3 {
    <#
    .SYNOPSIS
    Checks control L3.3
    
    .DESCRIPTION
    Checks CIS Microsoft SQL Server 2012 benchmark section 1.1.

    Checks CIS Microsoft SQL Server 2016 benchmark section 1.1.
    
    .EXAMPLE
    L3.3
    
    .NOTES
    Control L3.3 checks if Systems are timely patched and updated.
    #>
    [CmdletBinding()]

    param()

    Write-Host "###### Now checking Control L3.3"
    HTMLPrinter -OpeningTag "<h3>" -Content "Control L3.3" -ClosingTag "</h3>"

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 1.1.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 1.1.
    # Checks the productlevel and productversion.
    $SqlQuery = "SELECT
                    SERVERPROPERTY('ProductLevel') as SP_Installed,
                    SERVERPROPERTY('ProductVersion') as Version
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "The server contains the following Service Pack and Version." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Check if these match the expected versions." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("SP_Installed", "Version")
}

function L3.4 {
    <#
    .SYNOPSIS
    Checks control 3.4
    
    .DESCRIPTION
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.11
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.13
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.14
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.17
    Checks CIS Microsoft SQL Server 2012 benchmark section 3.2

    Checks CIS Microsoft SQL Server 2016 benchmark section 2.11
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.13
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.14
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.17
    Checks CIS Microsoft SQL Server 2016 benchmark section 3.2
    
    .EXAMPLE
    L3.4
    
    .NOTES
    Control 3.4 checks if systems don't use default passwords or backdoor accounts.
    The default port for MSSQL is als checked here since this seems the best place to do so.
    #>
    [CmdletBinding()]

    param ()

    Write-Host "###### Now checking Control L3.4"
    HTMLPrinter -OpeningTag "<h3>" -Content "Control L3.4" -ClosingTag "</h3>"

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.11.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.11.
    # Checks if the MSSQL Server does not use the default port 1433.
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
                    @value AS TCP_Port
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check that the server does not use the default TCP_Port 1433." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("TCP_Port")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.13.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.13.
    # Checks if the default 'sa' account is disabled.
    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.14.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.14.
    # Checks if the default 'sa' account has been renamed.
    $SqlQuery = "SELECT
                    SP.sid         AS SID,
                    SP.name        AS Name,
                    SP.is_disabled AS Is_Disabled
                FROM
                    sys.server_principals AS SP
                WHERE
                    SP.SID = 0x01
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the default 'sa' account is disabled (True)" -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the default 'sa' account has been renamed." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("SID", "Name", "Is_Disabled")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.17.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.17.
    # Checks if no login exists with the name 'sa'.
    $SqlQuery = "SELECT
                    SP.principal_id AS Principal_ID,
                    SP.name         AS Name,
                    SP.is_disabled  AS Is_Disabled
                FROM
                    sys.server_principals AS SP
                WHERE
                      SP.type = 'S'
                   OR SP.type = 'U'
                   OR SP.type = 'G'
                ORDER BY
                    SP.Principal_ID
                    ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if no login exists with the name 'sa', even if this is not the original 'sa' account." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Principal_ID", "Name", "Is_Disabled")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 3.2.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 3.2.
    # Checks if the guest user has it's rights revoked on the databases, with the exception of the msdb
    $SqlQuery = "SELECT
                    DB_NAME()            AS Database_Name,
                    'guest'              AS Database_User,
                    DP.[permission_name] AS Permission_Name,
                    DP.[state_desc]      AS State_Desc
                FROM
                    sys.database_permissions AS DP
                WHERE
                    DP.[grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest')
                ;"
    HTMLPrinter -OpeningTag "<p>" -Content "Check for each of the following databases if the 'CONNECT' permission has been revoked for the 'guest' user." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "The connect permission is required for the 'master', 'tempdb', 'msdb' databases. Therefore they can be ignored." -ClosingTag "</p>"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:DatabasesInfo) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $Dataset = DataCollector $SqlQuery
            HTMLPrinter -Table $Dataset -Columns @("Database_Name", "Database_User", "Permission_Name", "State_Desc")
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        HTMLPrinter -Table $Dataset -Columns @("DatabaseName", "Database_User", "permission_name", "state_desc")
    }
}

function L3.5 {
    <#
    .SYNOPSIS
    Checks control L3.5
    
    .DESCRIPTION
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.1
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.2
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.3
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.4
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.5
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.6
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.7
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.8
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.9
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.12
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.15
    Checks CIS Microsoft SQL Server 2012 benchmark section 2.16
    Checks CIS Microsoft SQL Server 2012 benchmark section 6.2
    Checks CIS Microsoft SQL Server 2012 benchmark section 7.1
    Checks CIS Microsoft SQL Server 2012 benchmark section 7.2

    Checks CIS Microsoft SQL Server 2016 benchmark section 2.1
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.2
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.3
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.4
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.5
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.6
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.7
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.8
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.9
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.12
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.15
    Checks CIS Microsoft SQL Server 2016 benchmark section 2.16
    Checks CIS Microsoft SQL Server 2016 benchmark section 6.2
    Checks CIS Microsoft SQL Server 2016 benchmark section 7.1
    Checks CIS Microsoft SQL Server 2016 benchmark section 7.2
    
    .EXAMPLE
    L3.5
    
    .NOTES
    Control 3.5 Checks if the OS does not run unnecessary services.
    However since the MSSQL Server does not have access to this information it only checks its own services.
    #>
    [CmdletBinding()]

    param()

    Write-Host "###### Now checking Control L3.5"
    HTMLPrinter -OpeningTag "<h3>" -Content "Control L3.5" -ClosingTag "</h3>"

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.1.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.1.
    # Checks if the option 'Ad Hoc Distributed Queries' is disabled.
    $SqlQuery = "SELECT name                      AS Name,
                        CAST(value AS int)        AS Value_Configured,
                        CAST(value_in_use AS int) AS Value_In_Use
                FROM
                    sys.configurations AS C
                WHERE
                    C.Name = 'Ad Hoc Distributed Queries'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'Add Hoc Distributed Queries' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Value_Configured", "Value_In_Use")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.2.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.2.
    # Checks if the option 'clr enabled' is disabled.
    $SqlQuery = "SELECT name                      AS Name,
                        CAST(value AS int)        AS Value_Configured,
                        CAST(value_in_use AS int) AS Value_In_Use
                FROM
                    sys.configurations AS C
                WHERE
                    C.Name = 'clr enabled'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'clr enabled' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Value_Configured", "Value_In_Use")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.3.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.3.
    # Checks if the option 'cross db ownership chaining' is disabled.
    $SqlQuery = "SELECT name                      AS Name,
                        CAST(value AS int)        AS Value_Configured,
                        CAST(value_in_use AS int) AS Value_In_Use
                FROM
                    sys.configurations AS C
                WHERE
                    C.Name = 'cross db ownership chaining'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'cross db ownership chaining' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Value_Configured", "Value_In_Use")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.4.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.4.
    # Checks if the option 'Database Mail XPs' is disabled.
    $SqlQuery = "SELECT name                      AS Name,
                        CAST(value AS int)        AS Value_Configured,
                        CAST(value_in_use AS int) AS Value_In_Use
                FROM
                    sys.configurations AS C
                WHERE
                    C.Name = 'Database Mail XPs'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'Database Mail XPs' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Value_Configured", "Value_In_Use")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.5.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.5.
    # Checks if the option 'Ole Automation Procedures' is disabled.
    $SqlQuery = "SELECT name                      AS Name,
                        CAST(value AS int)        AS Value_Configured,
                        CAST(value_in_use AS int) AS Value_In_Use
                FROM
                    sys.configurations AS C
                WHERE
                    C.Name = 'Ole Automation Procedures'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'Ole Automation Procedures' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Value_Configured", "Value_In_Use")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.6.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.6.
    # Checks if the option 'remote access' is disabled.
    $SqlQuery = "SELECT name                      AS Name,
                        CAST(value AS int)        AS Value_Configured,
                        CAST(value_in_use AS int) AS Value_In_Use
                FROM
                    sys.configurations AS C
                WHERE
                    C.Name = 'remote access'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'remote access' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Value_Configured", "Value_In_Use")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.7.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.7.
    # Checks if the option 'remote admin connections' is disabled if the server is not in a cluster.
    $SqlQuery = "SELECT name                      AS Name,
                        CAST(value AS int)        AS Value_Configured,
                        CAST(value_in_use AS int) AS Value_In_Use
                FROM
                    sys.configurations AS C
                WHERE
                      C.Name                        = 'remote admin connections'
                  AND SERVERPROPERTY('IsClustered') = 0
                ;"
    $Dataset = DataCollector $SqlQuery
    if ($Dataset.Rows.Count -gt 0) {
        HTMLPrinter -OpeningTag "<p>" -Content "Check if 'remote admin connections' is disabled (0)." -ClosingTag "</p>"
        HTMLPrinter -Table $Dataset -Columns @("Name", "Value_Configured", "Value_In_Use")
    }
    else {
        HTMLPrinter -OpeningTag "<p>" -Content "This server is in a cluster. Therefore the check for 'remote admin connections' does not apply." -ClosingTag "</p>"
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.8.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.8.
    # Checks if the option 'scan for startup procs' is disabled.
    $SqlQuery = "SELECT name                      AS Name,
                        CAST(value AS int)        AS Value_Configured,
                        CAST(value_in_use AS int) AS Value_In_Use
                FROM
                    sys.configurations AS C
                WHERE
                    C.Name = 'scan for startup procs'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'scan for startup procs' is disabled (0)" -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Note that this option might be enabled to use certain audit traces, stored procedures and replication." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Value_Configured", "Value_In_Use")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.9.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.9.
    # Checks if the option 'is_trustworthy_on' is disabled.
    HTMLPrinter -OpeningTag "<p>" -Content "Check for the following databases if they have the (is_trustworthy_on set to False)." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "The 'msdb' database is required to have 'is_trustworthy_on set to True.`n" -ClosingTag "</p>"
    HTMLPrinter -Table $Script:DatabasesInfo -Columns @("Name", "Is_Trustworthy_On")

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
                    @getValue                     AS Is_Hidden,
                    SERVERPROPERTY('IsClustered') AS Is_In_Cluster
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the server is hidden (1)." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "If the server is in a cluster it might be necessary to have this turned off." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Is_Hidden", "Is_In_Cluster")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.15.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.15.
    # Checks if the option 'xp_cmdshell' is disabled.
    $SqlQuery = "SELECT name                      AS Name,
                        CAST(value AS int)        AS Value_Configured,
                        CAST(value_in_use AS int) AS Value_In_Use
                FROM
                    sys.configurations AS C
                WHERE
                    C.Name = 'xp_cmdshell'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'xp_cmdshell' is disabled (0)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Value_Configured", "Value_In_Use")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 2.16.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 2.16.
    # Checks if the is_auto_close_on option is turned off for contained databases.
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the 'is_auto_close_on' option is set to 'False' for the databases with 'containment' not set to '0'." -ClosingTag "</p>"
    HTMLPrinter -Table $Script:DatabasesInfo -Columns @("Name", "Containment", "Containment_Desc", "Is_Auto_Close_On")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 6.2.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 6.2.
    # Checks if user defined CLR assemblies are set to 'SAFE_ACCESS'.
    $SqlQuery = "SELECT
                    A.name                AS Name,
                    A.permission_set_desc AS Permission_Set_Desc,
                    A.is_user_defined     AS Is_User_Defined
                FROM
                    sys.assemblies AS A
                ORDER BY
                    Is_User_Defined,
                    Permission_Set_Desc
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if all is_user_defined assemblies have 'SAFE_ACCESS' set under 'permission_set_desc'." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Permission_Set_Desc", "Is_User_Defined")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 7.1.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 7.1.
    # Checks if 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher.
    $SqlQuery = "SELECT 
                        DB_NAME() AS DatabaseName,
                        SK.*
                FROM
                    sys.symmetric_keys AS SK
                ;"
    HTMLPrinter -OpeningTag "<p>" -Content "Check for every databse if the 'algorithm_desc' is set to 'AES_128', 'AES_192' or 'AES_256'." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "If no output is returned for a database then this means that no symmetric key is available for that database.`n" -ClosingTag "</p>"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:DatabasesInfo) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $Dataset = DataCollector $SqlQuery
            HTMLPrinter -Table $Dataset -Columns @("*")
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        HTMLPrinter -Table $Dataset -Columns @("*")
    }

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 7.2.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 7.2.
    # Checks if 'Asymmetric Key Size' is set to 'RSA_2048'.
    $SqlQuery = "SELECT
                    DB_NAME()      AS Database_Name,
                    AK.name       AS Key_Name,
                    AK.key_length AS Key_Length
                FROM
                    sys.asymmetric_keys AS AK
                ;"
    HTMLPrinter -OpeningTag "<p>" -Content "Check for every databse if the 'key_length' is set to '2048'." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "If no output is returned for a database then this means that no asymmetric key is available for that database.`n" -ClosingTag "</p>"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:DatabasesInfo) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $Dataset = DataCollector $SqlQuery
            HTMLPrinter -Table $Dataset -Columns @("Database_Name", "Key_Name", "Key_Length")
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        HTMLPrinter -Table $Dataset -Columns @("Database_Name", "Key_Name", "key_Length")
    }
}

function L3.7 {
    <#
    .SYNOPSIS
    Checks control L3.7
    
    .DESCRIPTION
    Checks CIS Microsoft SQL Server 2012 benchmark section 5.1
    Checks CIS Microsoft SQL Server 2012 benchmark section 5.2
    Checks CIS Microsoft SQL Server 2012 benchmark section 5.3
    Checks CIS Microsoft SQL Server 2012 benchmark section 5.4

    Checks CIS Microsoft SQL Server 2016 benchmark section 5.1
    Checks CIS Microsoft SQL Server 2016 benchmark section 5.2
    Checks CIS Microsoft SQL Server 2016 benchmark section 5.3
    Checks CIS Microsoft SQL Server 2016 benchmark section 5.4
    
    .EXAMPLE
    L3.7
    
    .NOTES
    Control 3.7 checks if network and components are actively monitord.
    #>
    [CmdletBinding()]

    param()

    Write-Host "###### Now checking Control L3.7"
    HTMLPrinter -OpeningTag "<h3>" -Content "Control L3.7" -ClosingTag "</h3>"

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
                    ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles]
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if the 'NumberOfLogFiles' is 12 or higher." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "If the number is -1, this might mean that the 'Limit the number of error log files before they are recycled' checkmark is not checked." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("NumberOfLogFiles")

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 5.2.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 5.2.
    # Checks if the default trace is enabled.
    $SqlQuery = "SELECT name                      AS Name,
                        CAST(value AS int)        AS Value_Configured,
                        CAST(value_in_use AS int) AS Value_In_Use
                FROM
                    sys.configurations AS C
                WHERE
                    C.Name = 'default trace enabled'
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if 'default trace enabled' is enabled (1)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Name", "Value_Configured", "Value_In_Use")

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

    # This query is based on CIS Microsoft SQL Server 2012 benchmark section 5.4.
    # This query is based on CIS Microsoft SQL Server 2016 benchmark section 5.4.
    # Checks if the 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'.
    $SqlQuery = "SELECT
                    S.name                AS 'Audit_Name',
                    CASE
                        WHEN S.is_state_enabled = 1
                        THEN 'Y'
                        
                        WHEN S.is_state_enabled = 0
                        THEN 'N'
                    END                   AS 'Audit_Enabled',
                    S.type_desc           AS 'Write_Location',
                    SA.name               AS 'Audit_Speciication_Name',
                    CASE SA.is_state_enabled
                        WHEN 1
                        THEN 'Y'
                        
                        WHEN 0
                        THEN 'N'
                    END                   AS 'Audit_Specification_Enabled',
                    SAD.audit_action_name AS Audit_Action_Name,
                    SAD.audited_result    AS Audited_Result
                FROM
                         sys.server_audit_specification_details AS SAD
                    JOIN sys.server_audit_specifications        AS SA  ON SAD.server_specification_id = SA.server_specification_id
                    JOIN sys.server_audits                      AS S   ON SA.audit_guid               = S.audit_guid
                ORDER BY
                    Audit_Enabled,
                    Audit_Name,
                    Audit_Specification_Enabled,
                    Audit_Action_Name
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "3 Rows should be returned." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "For these rows check if both the 'Audit Enabled' and 'Audit Specification Enabled' are set to 'Y'." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Also check if 'audited_result' is set to 'SUCCESS AND FAILURE'." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("Audit_Name", "Audit_Enabled", "Write_Location", "Audit_Specification_Name", "Audit_Specification_Enabled", "Audit_Action_Name", "Audited_Result")
}

function UserManagement {
    <#
    .SYNOPSIS
    Checks Usermanagement for the database server and it's underlying databases.
    
    .DESCRIPTION
    Usermanagment is checked both on the server level and on the underlying databases.
    First the login to database user mapping is checked.

    Then Server level data is gathered.
    First every login is checked to see which roles they possess.
    Second every server non-fixed server role is checked to which rights they possess.
    Third every login is checked again to see which rights they possess that are granted outside of a role.

    Lastly the same checks from the server level are performed on the databases level.
    Depending on the flags the program was started with it will either check all databases or only the specified one.
    
    .EXAMPLE
    UserManagment
    
    .NOTES
    Depending on the amount of users and how their grants are managed this function may create a lot of data.
    #>

    Write-Host "###### Now checking User Management"
    HTMLPrinter -OpeningTag "<h3>" -Content "User Management" -ClosingTag "</h3>"

    # Maps each login to all it's corresponding database users.
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
    foreach($DataTable in $Dataset.Tables) {
        foreach($Row in $DataTable){
            $TempTable.ImportRow($Row)
        }
    }
    HTMLPrinter -Table $TempTable -Columns @("LoginName", "DBName", "UserName", "AliasName")

    # Step 1: Audit who is in server-level roles.
    $SqlQuery = "SELECT
                    @@SERVERNAME                     AS ServerName,
                    SUSER_NAME(RM.role_principal_id) AS ServerRole,
                    LGN.name                         AS MemberName,
                    LGN.type_desc                    AS Type_Desc,
                    LGN.create_date                  AS Date_Created,
                    LGN.modify_date                  AS Last_Modified
                FROM
                               sys.server_role_members AS RM
                    INNER JOIN sys.server_principals   AS LGN ON RM.member_principal_id = LGN.principal_id
                ORDER BY
                    ServerRole,
                    Type_Desc
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "A list of who is in server-level roles" -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("ServerName", "ServerRole", "MemberName", "Type_Desc", "Date_Created", "Last_Modified")

    # Step 2: Audit the permissions of non-fixed server-level roles.
    $SqlQuery = "SELECT
                    @@SERVERNAME                        AS ServerName,
                    PR.name                             AS RoleName,
                    PE.permission_name                  AS Permission_Name,
                    PE.state_desc                       AS State_Desc,
                    SUSER_NAME(PE.grantor_principal_id) AS Grantor,
                    PR.create_date                      AS Date_Created,
                    PR.modify_date                      AS Last_Modified
                FROM
                         sys.server_principals  AS PR
                    JOIN sys.server_permissions AS PE ON PE.grantee_principal_id = PR.principal_id
                WHERE
                    PR.type = 'R'
                ORDER BY
                    PR.principal_id,
                    State_Desc,
                    Permission_Name;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "A list of Server level roles, defining what they are, and what they can do." -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Fixed server roles are not shown." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("ServerName", "RoleName", "Permission_Name", "State_Desc", "Grantor", "Date_Created", "Last_Modified")

    # Step 3: Audit any Logins that have access to specific objects outside of a role.
    $SqlQuery = "SELECT
                    @@SERVERNAME                AS ServerName,
                    ISNULL(sch.name, osch.name) AS SchemaName,
                    ISNULL(o.name, '.')         AS ObjectName,
                    O.type_desc                 AS Type_Desc,
                    SPRIN.name                  AS Grantee,
                    GRANTOR.name                AS Grantor,
                    SPRIN.type_desc             AS Principal_Type_Desc,
                    SPER.permission_name        AS Permission_Name,
                    SPER.state_desc             AS Permission_State_Desc
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
                    Grantee,
                    Grantor,
                    Permission_State_Desc,
                    Permission_Name
                ;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "A list of permissions directly granted or denied to logins." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("ServerName", "SchemaName", "ObjectName", "Type_Desc", "Grantee", "Grantor", "Principal_Type_Desc", "Permission_Name", "Permission_State_Desc")

    # Step 4: Audit who has access to the database.
    $SqlQueryDBAccess = "SELECT
                    @@SERVERNAME                    AS ServerName,
                    DB_NAME()                       AS DatabaseName, 
                    DP.name                         AS UserName,
                    USER_NAME(SM.role_principal_id) AS RoleName,
                    SUSER_SNAME(DP.sid)             AS LoginName,
                    DP.type_desc                    AS LoginType,
                    DP.create_date                  AS Date_Created,
                    DP.modify_date                  AS Last_Modified
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
                    RoleName,
                    UserName
                ;"
    
    # Step 5: Audit roles on each database, defining what they are, and what they can do.
    $SqlQueryDBRoles ="SELECT
                    @@SERVERNAME                AS ServerName,
                    DB_NAME()                   AS DatabaseName,
                    DPRIN.name                  AS RoleName,
                    ISNULL(SCH.name, OSCH.name) AS SchemaName,
                    ISNULL(O.name, '.')         AS ObjectName,
                    DPERM.permission_name       AS Permission_Name,
                    DPERM.state_desc            AS State_Desc,
                    GRANTOR.name                AS Grantor,
                    DPRIN.create_date                  AS Date_Created,
                    DPRIN.modify_date                  AS Last_Modified
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
                    Rolename,
                    State_Desc,
                    Grantor,
                    Permission_Name
                ;"

    # Step 6: Audit any users that have access to specific objects outside of a role
    $SqlQueryDBRights = "SELECT
                    @@SERVERNAME                AS ServerName,
                    DB_NAME()                   AS DatabaseName,
                    ISNULL(SCH.name, OSCH.name) AS SchemaName,
                    ISNULL(O.name, '.')         AS ObjectName,
                    O.type_desc                 AS Type_Desc,
                    DPRIN.NAME                  AS Grantee,
                    SUSER_SNAME(DPRIN.sid)      AS LoginName,
                    GRANTOR.name                AS Grantor,
                    DPRIN.type_desc             AS Principal_Type_Desc,
                    DPERM.permission_name       AS Permission_Name,
                    DPERM.state_desc            AS Permission_State_Desc
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
                    Grantee,
                    Grantor,
                    Permission_State_Desc,
                    Permission_Name
                ;"

    if ($Script:AllDatabases) {
        foreach ($db in $Script:DatabasesInfo) {
            $Script:Database = $db.name
            SqlConnectionBuilder

            $Dataset = DataCollector $SqlQueryDBAccess
            HTMLPrinter -OpeningTag "<p>" -Content "A list of users and the roles they are in." -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("ServerName", "DatabaseName", "UserName", "RoleName", "LoginName", "LoginType", "Date_Created", "Last_Modified")

            $Dataset = DataCollector $SqlQueryDBRoles
            HTMLPrinter -OpeningTag "<p>" -Content "A list of Database level roles, defining what they are, and what they can do." -ClosingTag "</p>"
            HTMLPrinter -OpeningTag "<p>" -Content "Fixed database roles are not shown." -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("ServerName", "DatabaseName", "RoleName", "SchemaName", "ObjectName", "Permission_Name", "State_Desc", "Grantor", "Date_Created", "Last_Modified")

            $Dataset = DataCollector $SqlQueryDBRights
            HTMLPrinter -OpeningTag "<p>" -Content "Audit any users that have access to specific objects outside of a role" -ClosingTag "</p>"
            HTMLPrinter -Table $Dataset -Columns @("ServerName", "DatabaseName", "SchemaName", "ObjectName", "Type_Desc", "Grantee", "LoginName", "Grantor", "Principal_Type_Desc", "Permission_Name", "Permission_State_Desc")
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQueryDBAccess
        HTMLPrinter -OpeningTag "<p>" -Content "A list of users and the roles they are in." -ClosingTag "</p>"
        HTMLPrinter -Table $Dataset -Columns @("ServerName", "DatabaseName", "UserName", "RoleName", "LoginName", "LoginType", "Date_Created", "Last_Modified")

        $Dataset = DataCollector $SqlQueryDBRoles
        HTMLPrinter -OpeningTag "<p>" -Content "A list of Database level roles, defining what they are, and what they can do." -ClosingTag "</p>"
        HTMLPrinter -OpeningTag "<p>" -Content "Fixed database roles are not shown." -ClosingTag "</p>"
        HTMLPrinter -Table $Dataset -Columns @("ServerName", "DatabaseName", "RoleName", "SchemaName", "ObjectName", "Permission_Name", "State_Desc", "Grantor", "Date_Created", "Last_Modified")

        $Dataset = DataCollector $SqlQueryDBRights
        HTMLPrinter -OpeningTag "<p>" -Content "Audit any users that have access to specific objects outside of a role" -ClosingTag "</p>"
        HTMLPrinter -Table $Dataset -Columns @("ServerName", "DatabaseName", "SchemaName", "ObjectName", "Type_Desc", "Grantee", "LoginName", "Grantor", "Principal_Type_Desc", "Permission_Name", "Permission_State_Desc")   
    }
}

function HTMLPrinter {
    <#
    .SYNOPSIS
    TODO
    
    .DESCRIPTION
    TODO
    
    .EXAMPLE
    TODO
    
    .NOTES
    TODO
    #>
    [CmdletBinding()]

    param (
        # The opening tag.
        [string]
        $OpeningTag,

        # The content of the html.
        [string]
        $Content,

        # The closing tag.
        [string]
        $ClosingTag,

        [System.Data.DataTable]
        $Table,

        [array]
        $Columns
    )

    $TableCSS = @"
<style>l
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TH {border-width: 1px;padding: 3px; border-style: solid;border-color: black; background-color: #6495ED;}
TD {border-width: 1px;padding: 3px; border-style: solid;border-color: black;}
.odd  { background-color:#ffffff; }
.even { background-color:#dddddd; }
</style>
"@

    try { 
        if ($Content -eq "") {
            out-file -filepath $Script:Outfile -inputobject ($Table | ConvertTo-Html -Property $Columns -Fragment -PreContent $TableCSS) -append
        }
        else {
            out-file -filepath $Script:Outfile -InputObject $OpeningTag, $Content, $ClosingTag -append
        }
    }
    catch {
        Write-Host "An Error has occured."
    }
}





Startup
