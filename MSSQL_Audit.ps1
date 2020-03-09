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
    $Include = 'All'

    # TODO: Work on the XML configuration options.
    # # Specifies that a configuration file should be used for the parameters.
    # [parameter(ParameterSetName = "Configuration")]
    # [switch]
    # $Config,

    # # Specifies the configuration file to use for the script configuration.
    # # Defaults to ./configuration.xml
    # [parameter(ParameterSetName = "Configuration")]
    # [String[]]
    # $ConfigurationFile = "./configuration.xml"
)


# Server properties
$Script:IsClustered = $null
$Script:IsIntegratedSecurityOnly = $null
$Script:ProductLevel = $null
$Script:ProductVersion = $null

# Registery
$Script:HideInstance = $null
$Script:NumErrorLogs = $null
$Script:TcpPort = $null

# Tables
$Script:dbo__sysproxylogin = $null
$Script:master__sys__server_permissions = $null
$Script:sys__assemblies = $null
$Script:sys__asymmetric_keys = $null
$Script:sys__configurations = $null
$Script:sys__database_permissions = $null
$Script:sys__database_principals = $null
$Script:sys__server_audit_specification_details = $null
$Script:sys__server_audit_specifications = $null
$Script:sys__server_audits = $null
$Script:sys__server_permissions = $null
$Script:sys__server_principals = $null
$Script:sys__server_role_members = $null
$Script:sys__sql_logins = $null
$Script:sys__symmetric_keys = $null
$Script:sysproxies = $null

# Stored procedures
$Script:sp_change_users_login = $null
$Script:xp_loginconfig = $null

# @@Version
$Script:full_version = $null


# function Configuration_Parser {
#     <#
#     .SYNOPSIS
#     Parses the configuration file and fills the startup parameters.
    
#     .DESCRIPTION
#     Parses the XML configuration file that can be use provided on startup.
#     The info in this file will be used to fill in the parameters that can otherwise be provided on startup.
    
#     .EXAMPLE
#     Configuration_Parser
#     #>
#     [CmdletBinding()]
#     param()

#     #Read the xml config file.
#     [xml]$xml_configuration = Get-Content $ConfigurationFile
#     $mssql_xml_configuration = $xml_configuration.configuration.mssql

#     # Server
#     $Global:Server = $mssql_xml_Configuration.server.server_name

#     # AuthenticationMode
#     if ($mssql_xml_Configuration.server.authentication_mode -eq "Windows_Authentication") {
#         $Global:WindowsAuthentication = $true
#     }
#     elseif ($mssql_xml_Configuration.server.authentication_mode -eq "SQL_Authentication") {
#         $Global:SQLAuthentication = $true
#         $Global:Username = $mssql_xml_Configuration.username
#     }
#     else {
#         Write-Error -Message "Non-existing Authentication method provided in the config file." -Category InvalidArgument -ErrorAction Stop
#     }

#     # Username
#     $Global:Username = $mssql_xml_configuration.server.username
#     # Password
#     # Password is currently not supported, it must be entered manually when the script asks for it.

#     # Database
#     $Global:Database = $mssql_xml_configuration.server.database

#     # Include
#     # TODO add include to the configuration file.
# }


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


function SqlConnectionBuilder {
    <#
    .SYNOPSIS
    Builds and returns the SqlConnection object.
    
    .DESCRIPTION
    Creates a ConnectionString based on the global script variables $Global:Server and $Global:Database.
    
    .EXAMPLE
    SqlConnectionBuilder
    #>
    [CmdletBinding()]

    # "Integrated Security = True" means that the connection uses windows authentication.
    # The supplied credentials will be the credentials of owner of the powershell session.
    $Script:SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    if ($Script:WindowsAuthentication) {
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
    $SQLCommand.Connection = $Global:SqlConnection
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
                    @@VERSION AS Version
                ;"
    $Dataset = DataCollector $SqlQuery

    HTMLPrinter -OpeningTag "<h3 id='Server_version' class='headers'>" -Content "Server version" -ClosingTag "</h3>"
    HTMLPrinter -Table $Dataset -Columns @("Version")
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

    $startHTML = Get-Content ./Assets/Rapport_Builder/HTML_Snippets/Rapport_Start.html
    $endHTML = Get-Content ./Assets/Rapport_Builder/HTML_Snippets/Rapport_End.html
    $startCollapsable = Get-Content ./Assets/Rapport_Builder/HTML_Snippets/Collapsable_Start.html

    try {   
        if ($Table -ne $null) {
            Out-File -FilePath $Script:Outfile -Encoding utf8 -InputObject $startCollapsable -append
            Out-File -filepath $Script:Outfile -Encoding utf8 -inputobject ($Table | ConvertTo-Html -Property $Columns -Fragment) -append
            Out-File -FilePath $Script:Outfile -Encoding utf8 -InputObject "</div>" -append
        }
        elseif ($Content -ne "") {
            Out-File -filepath $Script:Outfile -Encoding utf8 -InputObject $OpeningTag, $Content, $ClosingTag -append
        }
        elseif ($HTMLStart) {
            Out-File -filepath $Script:Outfile -Encoding utf8 -InputObject $startHTML -Append
        }
        elseif ($HTMLEnd) {
            Out-File -filepath $Script:Outfile -Encoding utf8 -InputObject $endHTML -Append
        }
    }
    catch {
        Write-Host "An Error has occured."
    }
}


Main
