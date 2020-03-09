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
