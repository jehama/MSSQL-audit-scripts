[CmdletBinding(DefaultParameterSetName="None")]
# This initializes the parameters which were present when the script was launched.
param(
    # The MSSQL Server to connect to.
    [parameter(Mandatory = $true)]
    [String]
    $Server,

    # The database to connect to.
    # This parameter is optional. Only use this if you wish to audit a specific database.
    [parameter()]
    [String]
    $Database,

    # Sets authentication form to Windows Authentication.
    [parameter()]
    [switch]
    $WindowsAuthentication,

    # Sets authentication form to SQL Authentication.
    [parameter(ParameterSetName = "SQLAuthentication", Mandatory = $false)]
    [switch]
    $SQLAuthentication,

    # The username to authenticate with.
    # This is required when using SQL authentication, but has no effect when using Windows authentication.
    [parameter(ParameterSetName = "SQLAuthentication", Mandatory = $true)]
    [String]
    $Username
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

    Write-Output "#########################`nMSSQL audit tool`n#########################"

    if($SQLAuthentication) {
        $SecurePassword = Read-Host -AsSecureString "Enter password"
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $Script:Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }

    Write-Output "Using $Script:Server as target server"
    if ($Script:Database -ne "") {
        Write-Output "Using $Script:Database as target database"
        $Script:AllDatabases = $false
    }
    else {
        Write-Output "There Currently no database selected."
        Write-Output "Selecting database `"master`" instead"
        $Script:Database = "master"
        $Script:AllDatabases = $true
    }

    $Script:OriginalDatabase = $Script:Database

    SqlConnectionBuilder    

    CheckFullVersion
    GenerateDatabaseList
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

    # Obtains all logins and users from the MSSQL Server.
    UserObtainer

    test
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
    # It uses the credentials of the current user.
    # Using other credentials or SQL login is currently not supported.
    $Script:SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    if ($WindowsAuthentication) {
        $Script:SqlConnection.ConnectionString = "Server = $Script:Server; Database = $Script:Database; Integrated Security = True;"
    }
    if ($SQLAuthentication) {
        $Script:SqlConnection.ConnectionString = "Server = $Script:Server; Database = $Script:Database; User Id = $Username; Password = $Script:Password;"
    }
}

function DataCollector {
    <#
    .SYNOPSIS
    Collects data from the MSSQL DB.
    
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
        $SqlQuery
    )

    $SQLCommand = New-Object System.Data.SqlClient.SqlCommand
    $SQLCommand.CommandText = $SqlQuery
    $SQLCommand.Connection = $Script:SqlConnection
    $SQLAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
    $SQLAdapter.SelectCommand = $SQLCommand
    $Dataset = New-Object System.Data.DataSet
    $SqlAdapter.Fill($Dataset)

    $Dataset 
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

    $SqlQuery = "SELECT @@VERSION as Version"
    $Dataset = DataCollector $SqlQuery

    # Wrap is used because otherwise the whole value will not be showed in the output.
    Write-Output "The server currently has the following version:"
    $Dataset.Tables[0].Rows | Format-Table -HideTableHeaders -Wrap
}

function GenerateDatabaseList {
    <#
    .SYNOPSIS
    Generate list of databases.
    
    .DESCRIPTION
    Generates a list of databases on the server.
    This list is used for queries that are used on every database of the server.
    
    .EXAMPLE
    GenerateDatabaseList
    
    .NOTES
    General notes
    #>
    [CmdletBinding()]
    
    param ()

    $SqlQuery = " SELECT name
    FROM sys.databases;"
    $Script:ListOfDatabases = DataCollector $SqlQuery
    Write-Output "This server contains the following databases:"
    Write-Output $Script:ListOfDatabases.Tables[0].Rows | Format-Table -Wrap
}

function L1.1 {
    <#
    .SYNOPSIS
    Checks control L1.1
    
    .DESCRIPTION
    Checks CIS 4.1
    Checks CIS 4.2
    
    .EXAMPLE
    L1.1
    
    .NOTES
    Control L1.1 checks if passwords are periodically changed.
    #>
    [CmdletBinding()]

    param()

    Write-Output "###### Now checking Control L1.1"

    # This check is based on CIS 4.1.
    # Checks if the 'MUST_CHANGE' optino is set 'ON' on all SQL Authenticated Logins.
    # There is currently no query available to check this.
    Write-Output "Check if the 'MUST_CHANGE' option is set to 'ON' for all SQL Authenticated Logins."
    Write-Output "This check is only applicable immediately after the login is created or altered to force the password change."
    Write-Output "Once the password has been changed it is not possible to check if this option has forced the password change."
    Write-Output "There is currently no automated way to check this."
    Write-Output "1. Open 'SQL Server Management Studio'."
    Write-Output "2. Open 'Object Explorer' and connect to the target instance."
    Write-Output "3. Navigate to the 'Logins' tab in 'Object Explorer' and expand."
    Write-Output "4. Right click on the desired login and select 'Properties'."
    Write-Output "5. Verify the User must change password at next login checkbox is checked.`n"

    # This check is based on CIS 4.2.
    # Checks if the 'CHECK_EXPIRATION'option is set to 'ON' for all SQL Authenticated Logins.
    $SqlQuery = "SELECT l.[name],
                        'sysadmin membership' AS 'Access_Method',
                        l.is_expiration_checked
                FROM sys.sql_logins AS l
                UNION ALL
                SELECT l.[name],
                        'CONTROL SERVER' AS 'Access_Method',
                        l.is_expiration_checked
                FROM sys.sql_logins AS l
                JOIN sys.server_permissions AS p
                ON l.principal_id = p.grantee_principal_id;"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if SQL Authenticated Logins have the 'CHECK_EXPIRATION' option set to on."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

}

function L1.2 {
    <#
    .SYNOPSIS
    Checks control L1.2
    
    .DESCRIPTION
    Checks CIS 3.4
    Checks CIS 4.3
    
    .EXAMPLE
    L1.2
    
    .NOTES
    Control L1.2 checks if password are adequately enough.
    #>
    [CmdletBinding()]

    param()

    Write-Output "###### Now checking Control L1.2"

    # This query is based on CIS 3.4.
    # Checks if SQL authentication is not used in contained databases.
    $SqlQuery = "SELECT name AS DBUser, authentication_type
                FROM sys.database_principals
                WHERE name NOT IN ('dbo', 'Information_Schema', 'sys', 'guest')
                AND type IN ('U', 'S', 'G')"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if SQL authentication (authentication_type 2) is not used in contained databases."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 4.3.
    # Checks if the 'CHECK_POLICY' Option is set to 'True' for all SQL Authenticated Logins.
    $SqlQuery = "SELECT name,
                        is_disabled,
                        is_policy_checked
                FROM sys.sql_logins;"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'is_policy_checked' is set to 'True'."
    $Dataset.Tables[0].Rows | Format-Table -Wrap
}

function L1.3 {
    <#
    .SYNOPSIS
    Checks control L1.3
    
    .DESCRIPTION
    Checks CIS 3.1
    
    .EXAMPLE
    L1.3
    
    .NOTES
    Control L1.3 checks if two-factor authentication is used with untrusted zones.
    #>
    [CmdletBinding()]

    param()

    Write-Output "###### Now checking Control L1.3"

    # This query is based on CIS 3.1.
    # Checks if the 'Server Authentication' property is set to 'Windows Authentication Mode'.
    $SqlQuery = "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') as [login_mode];"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'login_mode' is set to 'Windows Authentication Mode' only (1)."
    $Dataset.Tables[0].Rows | Format-Table -Wrap
}

function L2.1 {
    <#
    .SYNOPSIS
    Checks control L2.1
    
    .DESCRIPTION
    Checks CIS 3.8
    Checks CIS 3.11

    .EXAMPLE
    L2.1
    
    .NOTES
    Control 2.1 Checks if accounts only have the necessary access rights.
    #>
    [CmdletBinding()]

    param()

    Write-Output "###### Now checking Control L2.1"
    
    # This query is based on CIS 3.8.
    # Checks if only the default permissions specified by Microsoft are granted to the public server role.
    $SqlQuery = "SELECT *
                FROM master.sys.server_permissions
                WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE 'GRANT%');"
    $Dataset = DataCollector $SqlQuery
    Write-Output "The 'public' server role has the following permissions."
    Write-Output "These extra permissions apply to every login on the server. Therefore it should only have the default permissions."
    Write-Output "These are:"
    Write-Output "state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and class_desc = 'SERVER')"
    Write-Output "state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 2)"
    Write-Output "state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 3)"
    Write-Output "state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 4)"
    Write-Output "state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 5)"
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 3.11.
    # Checks if the 'msdb' user does not have access to the SQL Agent proxies.
    $SqlQuery = "SELECT sp.name AS proxyname
                FROM dbo.sysproxylogin spl
                JOIN sys.database_principals dp
                ON dp.sid = spl.sid
                JOIN sysproxies sp
                ON sp.proxy_id = spl.proxy_id;"
    $Script:Database = "msdb"
    SqlConnectionBuilder
    $Dataset = DataCollector $SqlQuery
    if ($Dataset.Tables[0].Rows.Count -gt 0) {
        Write-Output "The 'msdb' database's 'public' role has been granted to the following proxies."
        Write-Output "These proxies may have higher privilages then the 'public' role. Therefore they should be removed.`n"
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }
    else {
        Write-Output "The 'msdb' database's 'public' role has not been granted access to proxies.`n"
    }
    $Script:Database = $Script:OriginalDatabase
    SqlConnectionBuilder
}

function L2.2 {
    <#
    .SYNOPSIS
    Checks control L2.2
    
    .DESCRIPTION
    Checks CIS 3.5  TODO: implement CIS recommendation
    Checks CIS 3.6  TODO: implement CIS recommendation
    Checks CIS 3.7  TODO: implement CIS recommendation
    Checks CIS 3.9
    Checks CIS 3.10
    
    .EXAMPLE
    L2.2
    
    .NOTES
    Control 2.2 Checks if accounts  and access rights are authorized.
    #>
    [CmdletBinding()]

    param()

    Write-Output "###### Now checking Control L2.2"
    
    # This query is based on CIS 3.9
    # Checks if the Windows 'BUILTIN' groups are not SQL Logins.
    $SqlQuery = "SELECT pr.[name],
                        pe.[permission_name],
                        pe.[state_desc]
                FROM sys.server_principals pr
                JOIN sys.server_permissions pe
                ON pr.principal_id = pe.grantee_principal_id;"
    $Dataset = DataCollector $SqlQuery
    Write-Output "The following groups or accounts have been added as SQL Server Logins."
    Write-Output "Check if none of these logins are Windows BUILTIN groups or accounts.`n"
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 3.10.
    # Checks if it is not allowed for 'WINDOWS_GROUP' users to be added to the server.
    $SqlQuery = "SELECT pr.[name] AS LocalGroupName,
                        pr.[type_desc],
                        pe.[permission_name],
                        pe.[state_desc]
                FROM sys.server_principals pr
                JOIN sys.server_permissions pe
                ON pr.[principal_id] = pe.[grantee_principal_id];"
                # WHERE pr.[type_desc] = 'WINDOWS_GROUP';"
                # AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) +'%';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "The following groups or accounts have been added as SQL Server Logins."
    Write-Output "Check if there are no WINDOWS_GROUP users. (type_desc = WINDOWS_GROUP and LocalGroupName contains the MachineName)`n"
    $Dataset.Tables[0].Rows | Format-Table -Wrap
}
function L2.8 {
    <#
    .SYNOPSIS
    Checks control L2.8
    
    .DESCRIPTION
    Checks CIS 3.3
    
    .EXAMPLE
    L2.8
    
    .NOTES
    Control 2.8 Checks if useraccounts and administratoraccounts are periodically evaluated.
    #>
    [CmdletBinding()]

    param()

    Write-Output "###### Now checking Control L2.8"
    
    # This query is based on CIS 3.3
    # Checks if 'Orphaned Users' are dropped from SQL Server Databases.
    $SqlQuery = "EXEC sp_change_users_login @Action='Report';"
    $Dataset = DataCollector $SqlQuery
    if ($Dataset.Tables[0].Rows.Count -gt 0) {
        Write-Output "The following accounts are 'orphaned'."
        Write-Output "These accounts should probably be removed.`n"
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }
    else {
        Write-Output "There are no accounts that are 'orphaned'.`n"
    }
}

function L3.3 {
    <#
    .SYNOPSIS
    Checks control L3.3
    
    .DESCRIPTION
    Checks CIS 1.1.
    
    .EXAMPLE
    L3.3
    
    .NOTES
    Control L3.3 checks if Systems are timely patched and updated.
    #>
    [CmdletBinding()]

    param()

    Write-Output "###### Now checking Control L3.3"

    # This query is based on CIS 1.1.
    # Checks the productlevel and productversion.
    $SqlQuery = "SELECT SERVERPROPERTY('ProductLevel') as SP_installed,
                        SERVERPROPERTY('ProductVersion') as Version;"
    $Dataset = DataCollector $SqlQuery
    Write-Output "The server contains the following Service Pack and Version."
    Write-Output "Check if these match the expected versions."
    $Dataset.Tables[0].Rows | Format-Table -Wrap
}

function L3.4 {
    <#
    .SYNOPSIS
    Checks control 3.4
    
    .DESCRIPTION
    Checks CIS 2.11
    Checks CIS 2.13
    Checks CIS 2.14
    Checks CIS 2.17
    Checks CIS 3.2
    
    .EXAMPLE
    L3.4
    
    .NOTES
    Control 3.4 checks if systems don't use default passwords or backdoor accounts.
    The default port for MSSQL is als checked here since this seems the best place to do so.
    #>
    [CmdletBinding()]

    param ()

    Write-Output "###### Now Checking Control L3.4"

    # This query is based on CIS 2.11.
    # Checks if the MSSQL Server does not use the default port 1433.
    $SqlQuery = "DECLARE @value nvarchar (256);
                EXECUTE master.dbo.xp_instance_regread
                    N'HKEY_LOCAL_MACHINE',
                    N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib\Tcp\IPALL',
                    N'TcpPort',
                    @value OUTPUT,
                    N'no_output';
                    
                SELECT @value AS TCP_Port"
    $DataSet = DataCollector $SqlQuery
    Write-Output "Check that the server does not use the default TCP_Port 1433."
    $DataSet.Tables[0].Rows | Format-Table -Wrap
    
    # This query is based on CIS 2.13.
    # Checks if the default 'sa' account is disabled.
    $SqlQuery = "SELECT sid,
                        name,
                        is_disabled
                FROM sys.server_principals
                WHERE sid = 0x01;"
    $DataSet = DataCollector $SqlQuery
    Write-Output "Check if the default 'sa' account is disabled (True)"
    $DataSet.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.14.
    # Checks if the default 'sa' account is renamed.
    $SqlQuery = "SELECT sid,
                        name,
                        is_disabled
                FROM sys.server_principals
                WHERE sid = 0x01;"
    $DataSet = DataCollector $SqlQuery
    Write-Output "Check if the default 'sa' account has been renamed."
    Write-Output "If the 'sa' account has already been disabled this check might be skipped."
    $DataSet.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.17.
    # Checks if no login exists with the name 'sa'.
    $SqlQuery = "SELECT principal_id,
                        name,
                        is_disabled
                FROM sys.server_principals;"
    $DataSet = DataCollector $SqlQuery
    Write-Output "Check if no login exists with the name 'sa', even if this is not the original 'sa' account."
    Write-Output "If the principal ID of the sa account is 1 and it is disabled this check  might be skipped."
    $DataSet.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 3.2.
    # Checks if the guest user has it's rights revoked on the databases, with the exception of the msdb
    $SqlQuery = "SELECT DB_NAME() AS DatabaseName,
                        'guest' AS Database_User,
                        [permission_name],
                        [state_desc]
                FROM sys.database_permissions
                WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest');"
    Write-Output "Check for each of the following databases if the 'CONNECT' permission has been revoked."
    Write-Output "The connect permission is required for the 'master', 'tempdb', 'msdb' databases. Therefore they can be ignored." 
    if ($Script:AllDatabases) {
        foreach ($db in $Script:ListOfDatabases.Tables[0]) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $DataSet = DataCollector $SqlQuery
            $DataSet.Tables[0].Rows | Format-Table -Wrap
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }
}

function L3.5 {
    <#
    .SYNOPSIS
    Checks control L3.5
    
    .DESCRIPTION
    Checks CIS 2.1
    Checks CIS 2.2
    Checks CIS 2.3
    Checks CIS 2.4
    Checks CIS 2.5
    Checks CIS 2.6
    Checks CIS 2.7
    Checks CIS 2.8
    Checks CIS 2.9
    Checks CIS 2.10
    Checks CIS 2.12
    Checks CIS 2.15
    Checks CIS 2.16
    Checks CIS 6.2
    Checks CIS 7.1
    Checks CIS 7.2
    
    .EXAMPLE
    L3.5
    
    .NOTES
    Control 3.5 Checks if the OS does not run unnecessary services.
    However since the MSSQL Server does not have access to this information it only checks its own services.
    #>
    [CmdletBinding()]

    param()

    Write-Output "###### Now checking Control L3.5"

    # This query is based on CIS 2.1.
    # Checks if the option 'Ad Hoc Distributed Queries' is disabled.
    $SqlQuery = "SELECT name,
                        CAST(value as int) as value_configured,
                        CAST(value_in_use as int) as value_in_use
                FROM sys.configurations
                WHERE name = 'Ad Hoc Distributed Queries';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'Add Hoc Distributed Queries' is disabled (0)."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.2.
    # Checks if the option 'clr enabled' is disabled.
    $SqlQuery = "SELECT name,
                        CAST(value as int) as value_configured,
                        CAST(value_in_use as int) as value_in_use
                FROM sys.configurations
                WHERE name = 'clr enabled';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'clr enabled' is disabled (0)."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.3.
    # Checks if the option 'cross db ownership chaining' is disabled.
    $SqlQuery = "SELECT name,
                        CAST(value as int) as value_configured,
                        CAST(value_in_use as int) as value_in_use
                FROM sys.configurations
                WHERE name = 'cross db ownership chaining';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'cross db ownership chaining' is disabled (0)."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.4.
    # Checks if the option 'Database Mail XPs' is disabled.
    $SqlQuery = "SELECT name,
                        CAST(value as int) as value_configured,
                        CAST(value_in_use as int) as value_in_use
                FROM sys.configurations
                WHERE name = 'Database Mail XPs';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'Database Mail XPs' is disabled (0)."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.5.
    # Checks if the option 'Ole Automation Procedures' is disabled.
    $SqlQuery = "SELECT name,
                        CAST(value as int) as value_configured,
                        CAST(value_in_use as int) as value_in_use
                FROM sys.configurations
                WHERE name = 'Ole Automation Procedures';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'Ole Automation Procedures' is disabled (0)."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.6.
    # Checks if the option 'remote access' is disabled.
    $SqlQuery = "SELECT name,
                        CAST(value as int) as value_configured,
                        CAST(value_in_use as int) as value_in_use
                FROM sys.configurations
                WHERE name = 'remote access';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'remote access' is disabled (0)."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.7.
    # Checks if the option 'remote admin connections' is disabled if the server is not in a cluster.
    $SqlQuery = "SELECT name,
                        CAST(value as int) as value_configured,
                        CAST(value_in_use as int) as value_in_use
                FROM sys.configurations
                WHERE name = 'remote admin connections'
                AND SERVERPROPERTY('IsClustered') = 0;"
    $Dataset = DataCollector $SqlQuery
    if ($Dataset.Tables[0].Rows.Count -gt 0) {
        Write-Output "Check if 'remote admin connections' is disabled (0)."
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }
    else {
        Write-Output "This server is in a cluster. Therefore the check for 'remote admin connections' does not apply."
    }

    # This query is based on CIS 2.8.
    # Checks if the option 'scan for startup procs' is disabled.
    $SqlQuery = "SELECT name,
                        CAST(value as int) as value_configured,
                        CAST(value_in_use as int) as value_in_use
                FROM sys.configurations
                WHERE name = 'scan for startup procs';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'scan for startup procs' is disabled (0)"
    Write-Output "Note that this option might be enabled to use certain audit traces, stored procedures and replication."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.9.
    # Checks if the option 'is_trustworthy_on' is disabled.
    $SqlQuery = "SELECT name,
                        is_trustworthy_on
                FROM sys.databases;"
                # WHERE is_trustworthy_on = 1
                # AND name != 'msdb';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check for the following databases if they have the (is_trustworthy_on set to False)."
    Write-Output "The 'msdb' database is required to have 'is_trustworthy_on set to True.`n"
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This check is based on CIS 2.10.
    # There is currently no query available to check this.
    Write-Output "Check if there are no unnecessary SQL Server Protocols are enabled."
    Write-Output "To check this follow the following steps."
    Write-Output "1. Open SQL Server Configuration Manager"
    Write-Output "2. Go to the SQL Server Network Configuration."
    Write-Output "3. Ensure that only required protocols are enabled."

    # This query is based on CIS 2.12.
    # Checks if the server is hidden. If the server is in a cluster it might be necessary to have this turned off.
    $SqlQuery = "DECLARE @getValue INT;
                EXEC master..xp_instance_regread
                    @rootkey = N'HKEY_LOCAL_MACHINE',
                    @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
                    @value_name = N'HideInstance',
                    @value = @getValue OUTPUT;
                SELECT @getvalue as is_hidden, SERVERPROPERTY('IsClustered') as is_in_cluster;"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if the server is hidden (1)."
    Write-Output "If the server is in a cluster it might be necessary to have this turned off."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.15.
    # Checks if the option 'xp_cmdshell' is disabled.
    $SqlQuery = "SELECT name,
                        CAST(value as int) as value_configured,
                        CAST(value_in_use as int) as value_in_use
                FROM sys.configurations
                WHERE name = 'xp_cmdshell';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'xp_cmdshell' is disabled (0)."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 2.16.
    # Checks if the is_auto_close_on option is turned off for contained databases.
    $SqlQuery = "SELECT name,
                        containment,
                        containment_desc,
                        is_auto_close_on
                FROM sys.databases;"
                # WHERE containment <> 0;"
    $Dataset = DataCollector $SqlQuery
    if ($Dataset.Tables[0].Rows.Count -gt 0) {
        Write-Output "Check if the 'is_auto_close_on' option is set to 'False' for the databases with 'containment' not set to '0'."
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }

    # This query is based on CIS 6.2.
    # Checks if user defined CLR assemblies are set to 'SAFE_ACCESS'.
    $SqlQuery = "SELECT name,
                        permission_set_desc,
                        is_user_defined
                FROM sys.assemblies;"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if all is_user_defined assemblies have 'SAFE_ACCESS' set under 'permission_set_desc'."
    $Dataset.Tables[0].Rows |Format-Table -Wrap

    # This query is based on CIS 7.1.
    # Checks if 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher.
    $SqlQuery = "SELECT *
                FROM sys.symmetric_keys;"
    Write-Output "Check for every databse if the 'algorithm_desc' is set to 'AES_128', 'AES_192' or 'AES_256'."
    Write-Output "If no output is returned for a database then this means that no symmetric key is available for that database.`n"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:ListOfDatabases.Tables[0]) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $DataSet = DataCollector $SqlQuery
            $DataSet.Tables[0].Rows | Format-Table -Wrap
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }

    # This query is based on CIS 7.2.
    # Checks if 'Asymmetric Key Size' is set to 'RSA_2048'.
    $SqlQuery = "SELECT db_name() AS Database_name,
                        name AS Key_Name,
                        key_length
                FROM sys.asymmetric_keys;"
    Write-Output "Check for every databse if the 'key_length' is set to '2048'."
    Write-Output "If no output is returned for a database then this means that no asymmetric key is available for that database.`n"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:ListOfDatabases.Tables[0]) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $DataSet = DataCollector $SqlQuery
            $DataSet.Tables[0].Rows | Format-Table -Wrap
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }
}

function L3.7 {
    <#
    .SYNOPSIS
    Checks control L3.7
    
    .DESCRIPTION
    Checks CIS 5.1
    Checks CIS 5.2
    Checks CIS 5.3
    Checks CIS 5.4
    
    .EXAMPLE
    L3.7
    
    .NOTES
    Control 3.7 checks if network and components are actively monitord.
    #>
    [CmdletBinding()]

    param()

    Write-Output "###### Now checking Control L3.7"

    # This query is based on CIS 5.1.
    # Checks if the maximum number of error log files is set greater than or equal to 12.
    $SqlQuery = "DECLARE @NumErrorLogs int;

                EXEC master.sys.xp_instance_regread
                    N'HKEY_LOCAL_MACHINE',
                    N'Software\Microsoft\MSSQLSERVER\MSSQLSERVER',
                    N'NumErrorLogs',
                    @NumErrorLogs OUTPUT;

                SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if the 'NumberOfLogFiles' is 12 or higher."
    Write-Output "If the number is -1, this might mean that the 'Limit the number of error log files before they are recycled' checkmark is not checked."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 5.2.
    # Checks if the default trace is enabled.
    $SqlQuery = "SELECT name,
                        CAST(value as int) as value_configured,
                        CAST(value_in_use as int) as value_in_use
                FROM sys.configurations
                WHERE name = 'default trace enabled';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if 'default trace enabled' is enabled (1)."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 5.3.
    # Checks if the 'Login Auditing' is set to 'faled logins'
    $SqlQuery = "EXEC xp_loginconfig 'audit level';"
    $Dataset = DataCollector $SqlQuery
    Write-Output "Check if the 'audit level' is configured to failure."
    Write-Output "A value of 'all' is also accepted, however it is recommended to check this with the SQL Server audit feature."
    $Dataset.Tables[0].Rows | Format-Table -Wrap

    # This query is based on CIS 5.4.
    # Checks if the 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'.
    $SqlQuery = "SELECT S.name AS 'Audit Name',
                        CASE S.is_state_enabled
                            WHEN 1 THEN 'Y'
                            WHEN 0 THEN 'N'
                            END
                            AS 'Audit Enabled',
                        S.type_desc AS 'Write Location',
                        SA.name AS 'Audit Speciication Name',
                        CASE SA.is_state_enabled
                            WHEN 1 THEN 'y'
                            WHEN 0 THEN 'N'
                            END
                            AS 'Audit Specification Enabled',
                        SAD.audit_action_name,
                        SAD.audited_result
                FROM sys.server_audit_specification_details AS SAD
                JOIN sys.server_audit_specifications AS SA
                    ON SAD.server_specification_id = SA.server_specification_id
                JOIN sys.server_audits AS S
                    ON SA.audit_guid = S.audit_guid;"
    $Dataset = DataCollector $SqlQuery
    Write-Output "3 Rows should be returned."
    Write-Output "For these rows check if both the 'Audit Enabled' and 'Audit Specification Enabled' are set to 'Y'."
    Write-Output "Also check if 'audited_result' is set to 'SUCCESS AND FAILURE'."
    $Dataset.Tables[0].Rows | Format-Table -Wrap
}

function UserObtainer {
    <#
    .SYNOPSIS
    Obtains all logins and users from the MSSQL Server.
    
    .DESCRIPTION
    Obtains all logins and users from the MSSQL Server.
    
    .EXAMPLE
    UserObtainer
    
    .NOTES
    Logins are used for server authentication, and users are used for database authorization.
    #>
    [CmdletBinding()]

    param()

    Write-Output "###### Now retrieving all Logins and Users."

    # Maps each login to all it's corresponding database users.
    $SqlQuery = "EXEC sp_MSloginmappings;"
    $Dataset = DataCollector $SqlQuery
    Write-Output "These tables contain every login on the server and their corresponding databases."
    $Dataset.Tables.Rows | Format-Table -Wrap

    Write-Output "###### Now retrieving all databases users and their permissions."

    # Shows all databases and the permissions users have in them.
    # Currently using a script from stack overflow. 
    # Obtained from: https://stackoverflow.com/questions/7048839/sql-server-query-to-find-all-permissions-access-for-all-users-in-a-database answer from Sean Rose answered May 4 '15 at 22:04
    $SqlQuery = "/*
    Security Audit Report
    1) List all access provisioned to a SQL user or Windows user/group directly
    2) List all access provisioned to a SQL user or Windows user/group through a database or application role
    3) List all access provisioned to the public role
    
    Columns Returned:
    UserType        : Value will be either 'SQL User', 'Windows User', or 'Windows Group'.
                      This reflects the type of user/group defined for the SQL Server account.
    DatabaseUserName: Name of the associated user as defined in the database user account.  The database user may not be the
                      same as the server user.
    LoginName       : SQL or Windows/Active Directory user account.  This could also be an Active Directory group.
    Role            : The role name.  This will be null if the associated permissions to the object are defined at directly
                      on the user account, otherwise this will be the name of the role that the user is a member of.
    PermissionType  : Type of permissions the user/role has on an object. Examples could include CONNECT, EXECUTE, SELECT
                      DELETE, INSERT, ALTER, CONTROL, TAKE OWNERSHIP, VIEW DEFINITION, etc.
                      This value may not be populated for all roles.  Some built in roles have implicit permission
                      definitions.
    PermissionState : Reflects the state of the permission type, examples could include GRANT, DENY, etc.
                      This value may not be populated for all roles.  Some built in roles have implicit permission
                      definitions.
    ObjectType      : Type of object the user/role is assigned permissions on.  Examples could include USER_TABLE,
                      SQL_SCALAR_FUNCTION, SQL_INLINE_TABLE_VALUED_FUNCTION, SQL_STORED_PROCEDURE, VIEW, etc.
                      This value may not be populated for all roles.  Some built in roles have implicit permission
                      definitions.
    Schema          : Name of the schema the object is in.
    ObjectName      : Name of the object that the user/role is assigned permissions on.
                      This value may not be populated for all roles.  Some built in roles have implicit permission
                      definitions.
    ColumnName      : Name of the column of the object that the user/role is assigned permissions on. This value
                      is only populated if the object is a table, view or a table value function.
    */
    
        --1) List all access provisioned to a SQL user or Windows user/group directly
        SELECT
            [UserType] = CASE princ.[type]
                             WHEN 'S' THEN 'SQL User'
                             WHEN 'U' THEN 'Windows User'
                             WHEN 'G' THEN 'Windows Group'
                         END,
            [DatabaseUserName] = princ.[name],
            [LoginName]        = ulogin.[name],
            [Role]             = NULL,
            [PermissionType]   = perm.[permission_name],
            [PermissionState]  = perm.[state_desc],
            [ObjectType] = CASE perm.[class]
                               WHEN 1 THEN obj.[type_desc]        -- Schema-contained objects
                               ELSE perm.[class_desc]             -- Higher-level objects
                           END,
            [Schema] = objschem.[name],
            [ObjectName] = CASE perm.[class]
                               WHEN 3 THEN permschem.[name]       -- Schemas
                               WHEN 4 THEN imp.[name]             -- Impersonations
                               ELSE OBJECT_NAME(perm.[major_id])  -- General objects
                           END,
            [ColumnName] = col.[name]
        FROM
            --Database user
            sys.database_principals            AS princ
            --Login accounts
            LEFT JOIN sys.server_principals    AS ulogin    ON ulogin.[sid] = princ.[sid]
            --Permissions
            LEFT JOIN sys.database_permissions AS perm      ON perm.[grantee_principal_id] = princ.[principal_id]
            LEFT JOIN sys.schemas              AS permschem ON permschem.[schema_id] = perm.[major_id]
            LEFT JOIN sys.objects              AS obj       ON obj.[object_id] = perm.[major_id]
            LEFT JOIN sys.schemas              AS objschem  ON objschem.[schema_id] = obj.[schema_id]
            --Table columns
            LEFT JOIN sys.columns              AS col       ON col.[object_id] = perm.[major_id]
                                                               AND col.[column_id] = perm.[minor_id]
            --Impersonations
            LEFT JOIN sys.database_principals  AS imp       ON imp.[principal_id] = perm.[major_id]
        WHERE
            princ.[type] IN ('S','U','G')
            -- No need for these system accounts
            AND princ.[name] NOT IN ('sys', 'INFORMATION_SCHEMA')
    
    UNION
    
        --2) List all access provisioned to a SQL user or Windows user/group through a database or application role
        SELECT
            [UserType] = CASE membprinc.[type]
                             WHEN 'S' THEN 'SQL User'
                             WHEN 'U' THEN 'Windows User'
                             WHEN 'G' THEN 'Windows Group'
                         END,
            [DatabaseUserName] = membprinc.[name],
            [LoginName]        = ulogin.[name],
            [Role]             = roleprinc.[name],
            [PermissionType]   = perm.[permission_name],
            [PermissionState]  = perm.[state_desc],
            [ObjectType] = CASE perm.[class]
                               WHEN 1 THEN obj.[type_desc]        -- Schema-contained objects
                               ELSE perm.[class_desc]             -- Higher-level objects
                           END,
            [Schema] = objschem.[name],
            [ObjectName] = CASE perm.[class]
                               WHEN 3 THEN permschem.[name]       -- Schemas
                               WHEN 4 THEN imp.[name]             -- Impersonations
                               ELSE OBJECT_NAME(perm.[major_id])  -- General objects
                           END,
            [ColumnName] = col.[name]
        FROM
            --Role/member associations
            sys.database_role_members          AS members
            --Roles
            JOIN      sys.database_principals  AS roleprinc ON roleprinc.[principal_id] = members.[role_principal_id]
            --Role members (database users)
            JOIN      sys.database_principals  AS membprinc ON membprinc.[principal_id] = members.[member_principal_id]
            --Login accounts
            LEFT JOIN sys.server_principals    AS ulogin    ON ulogin.[sid] = membprinc.[sid]
            --Permissions
            LEFT JOIN sys.database_permissions AS perm      ON perm.[grantee_principal_id] = roleprinc.[principal_id]
            LEFT JOIN sys.schemas              AS permschem ON permschem.[schema_id] = perm.[major_id]
            LEFT JOIN sys.objects              AS obj       ON obj.[object_id] = perm.[major_id]
            LEFT JOIN sys.schemas              AS objschem  ON objschem.[schema_id] = obj.[schema_id]
            --Table columns
            LEFT JOIN sys.columns              AS col       ON col.[object_id] = perm.[major_id]
                                                               AND col.[column_id] = perm.[minor_id]
            --Impersonations
            LEFT JOIN sys.database_principals  AS imp       ON imp.[principal_id] = perm.[major_id]
        WHERE
            membprinc.[type] IN ('S','U','G')
           -- No need for these system accounts
            AND membprinc.[name] NOT IN ('sys', 'INFORMATION_SCHEMA')
    
    UNION
    
        --3) List all access provisioned to the public role, which everyone gets by default
        SELECT
            [UserType]         = '{All Users}',
            [DatabaseUserName] = '{All Users}',
            [LoginName]        = '{All Users}',
            [Role]             = roleprinc.[name],
            [PermissionType]   = perm.[permission_name],
            [PermissionState]  = perm.[state_desc],
            [ObjectType] = CASE perm.[class]
                               WHEN 1 THEN obj.[type_desc]        -- Schema-contained objects
                               ELSE perm.[class_desc]             -- Higher-level objects
                           END,
            [Schema] = objschem.[name],
            [ObjectName] = CASE perm.[class]
                               WHEN 3 THEN permschem.[name]       -- Schemas
                               WHEN 4 THEN imp.[name]             -- Impersonations
                               ELSE OBJECT_NAME(perm.[major_id])  -- General objects
                           END,
            [ColumnName] = col.[name]
        FROM
            --Roles
            sys.database_principals            AS roleprinc
            --Role permissions
            LEFT JOIN sys.database_permissions AS perm      ON perm.[grantee_principal_id] = roleprinc.[principal_id]
            LEFT JOIN sys.schemas              AS permschem ON permschem.[schema_id] = perm.[major_id]
            --All objects
            JOIN      sys.objects              AS obj       ON obj.[object_id] = perm.[major_id]
            LEFT JOIN sys.schemas              AS objschem  ON objschem.[schema_id] = obj.[schema_id]
            --Table columns
            LEFT JOIN sys.columns              AS col       ON col.[object_id] = perm.[major_id]
                                                               AND col.[column_id] = perm.[minor_id]
            --Impersonations
            LEFT JOIN sys.database_principals  AS imp       ON imp.[principal_id] = perm.[major_id]
        WHERE
            roleprinc.[type] = 'R'
            AND roleprinc.[name] = 'public'
            AND obj.[is_ms_shipped] = 0
    
    ORDER BY
        [UserType],
        [DatabaseUserName],
        [LoginName],
        [Role],
        [Schema],
        [ObjectName],
        [ColumnName],
        [PermissionType],
        [PermissionState],
        [ObjectType]
    "
    if ($Script:AllDatabases) {
        foreach ($db in $Script:ListOfDatabases.Tables[0]) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $DataSet = DataCollector $SqlQuery
            $DataSet.Tables[0].Rows | Format-Table -Wrap
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }
}

function test {
    <#
    **************************************************************************************************
    *** Server Permissions Audit ***
    **************************************************************************************************

    These queries are based on an existing script.
    This script is used for auditing the permissions that exist on a SQL Server. It will scan every
    database on the server.
    and return four record sets:
    1. Audit who is in server-level roles
    2. Audit roles on each database, defining what they are and what they can do
    3. Audit the roles that users are in
    4. Audit any users that have access to specific objects outside of a role

    NOTE: the script these queries are based on was written for MS SQL Server 2005 and uses undocumented system tables,
    rather than the standard MS procedures. It is likely that this script will not work in future versions of SQL Server.

    Created: 2010-05-07
    #>


    # Step 1: Audit who is in server-level roles
    $SqlQuery = "SELECT @@SERVERNAME AS ServerName,
                        DB_NAME() AS DatabaseName,
                        SUSER_NAME(rm.role_principal_id) AS ServerRole,
                        lgn.name AS MemberName
                FROM sys.server_role_members rm
                INNER JOIN sys.server_principals lgn
                    ON rm.role_principal_id >= 3
                    AND rm.role_principal_id <= 10
                    AND rm.member_principal_id = lgn.principal_id
                ORDER BY 1, 2, 3, 4;"
    $DataSet = DataCollector $SqlQuery
    Write-Output "A list of who is in server-level roles"
    $DataSet.Tables[0].Rows | Format-Table -Wrap
    
    # Step 2: Audit roles on each database, defining what they are, what they can do, and who belongs in them
    $SqlQuery ="SELECT @@SERVERNAME AS ServerName,
                        DB_NAME() AS DatabaseName,
                        dprin.name AS RoleName,
                        ISNULL(sch.name, osch.name) AS SchemaName,
                        ISNULL(o.name, '.') AS ObjectName,
                        dperm.permission_name,
                        dperm.state_desc,
                        grantor.name AS Grantor
                FROM sys.database_permissions dperm
                INNER JOIN sys.database_principals dprin
                    ON dperm.grantee_principal_id = dprin.principal_id
                INNER JOIN sys.database_principals grantor
                    ON dperm.grantor_principal_id = grantor.principal_id
                LEFT OUTER JOIN sys.schemas sch
                    ON dperm.major_id = sch.schema_id AND dperm.class = 3
                LEFT OUTER JOIN sys.all_objects o
                    ON dperm.major_id = o.OBJECT_ID AND dperm.class = 1
                LEFT OUTER JOIN sys.schemas osch
                    ON o.schema_id = osch.schema_id
                WHERE dprin.name <> 'public'
                AND dperm.type <> 'CO'
                AND dprin.type = 'R'
                ORDER BY 1, 2, 3, 4, 5, 6;"
    Write-Output "Audit roles on each database, defining what they are and what they can do"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:ListOfDatabases.Tables[0]) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $DataSet = DataCollector $SqlQuery
            $DataSet.Tables[0].Rows | Format-Table -Wrap
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }

    # Step 3: Audit the roles that users are in
    $SqlQuery = "SELECT
                    @@SERVERNAME    AS ServerName,
                    DB_NAME()       AS DatabaseName, 
                    CASE
                        WHEN (r.principal_id IS NULL) THEN 'PUBLIC'
                        ELSE                                r.name
                    END             AS RoleName,
                    u.name          AS UserName
                FROM
                    sys.database_principals u
                LEFT JOIN (sys.database_role_members m
                    JOIN sys.database_principals r
                        ON m.role_principal_id = r.principal_ID)
                    ON m.member_principal_id = u.principal_id
                ORDER BY 1, 2, 3, 4;"
    Write-Output "Audit the roles that users are in"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:ListOfDatabases.Tables[0]) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $DataSet = DataCollector $SqlQuery
            $DataSet.Tables[0].Rows | Format-Table -Wrap
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }

    # Step 4: Audit any users that have access to specific objects outside of a role
    $SqlQuery = "SELECT
                    @@SERVERNAME                AS ServerName,
                    DB_NAME()                   AS DatabaseName,
                    ISNULL(sch.name, osch.name) AS SchemaName,
                    ISNULL(o.name, '.')         AS ObjectName,
                    o.type_desc,
                    dprin.NAME                  AS Grantee,
                    grantor.name                AS Grantor,
                    dprin.type_desc             AS principal_type_desc,
                    dperm.permission_name,
                    dperm.state_desc            AS permission_state_desc
                FROM
                    sys.database_permissions dperm
                Inner JOIN sys.database_principals dprin
                    ON dperm.grantee_principal_id = dprin.principal_id
                INNER JOIN sys.database_principals grantor
                    ON dperm.grantor_principal_id = grantor.principal_id
                LEFT OUTER JOIN sys.schemas sch
                    ON dperm.major_id = sch.schema_id
                        AND dperm.class = 3
                LEFT OUTER JOIN sys.all_objects o
                    ON dperm.major_id = o.OBJECT_ID
                    AND dperm.class = 1
                LEFT OUTER JOIN sys.schemas osch
                    ON o.schema_id = osch.schema_id
                WHERE dprin.name <> 'public'
                AND dperm.type <> 'CO'
                AND dprin.type <> 'R'
                ORDER BY 1, 2, 3, 4, 5;"
    Write-Output "Audit any users that have access to specific objects outside of a role"
    if ($Script:AllDatabases) {
        foreach ($db in $Script:ListOfDatabases.Tables[0]) {
            $Script:Database = $db.name
            SqlConnectionBuilder
            $DataSet = DataCollector $SqlQuery
            $DataSet.Tables[0].Rows | Format-Table -Wrap
        }
        $Script:Database = $Script:OriginalDatabase
        SqlConnectionBuilder
    }
    else {
        $Dataset = DataCollector $SqlQuery
        $Dataset.Tables[0].Rows | Format-Table -Wrap
    }
}






Startup
