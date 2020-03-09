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
