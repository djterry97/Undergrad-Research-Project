New-Item localTraffic.csv -ErrorAction SilentlyContinue
New-Item remoteTraffic.csv -ErrorAction SilentlyContinue

Get-ChildItem | ForEach-Object{
    If ( $_.Name -like "*.csv"){
        Write-Host $_.Name
        $data = Import-Csv $_.Name 
        ForEach ($row in $data){
            If (($row.ipsrc -like "192.168.*") -and ($row.ipdst -like "192.168.*")){
                # Local Traffic
                $row | Export-Csv -path localTraffic.csv -Append -NoTypeInformation
            }
            ElseIf (($row.ipsrc -notlike "192.168.*") -or ($row.ipdst -notlike "192.168.*") -and ($row.ipsrc -ne "")){
                # Remote Traffic
                $row | Export-Csv -path remoteTraffic.csv -Append -NoTypeInformation
            }
        }
    }
}