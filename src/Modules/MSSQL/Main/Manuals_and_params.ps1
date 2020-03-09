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
