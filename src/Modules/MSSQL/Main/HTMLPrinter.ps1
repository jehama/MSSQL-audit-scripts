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
