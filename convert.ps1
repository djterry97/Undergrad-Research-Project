Get-ChildItem "C:\Users\dylan\Documents\captures" | Foreach-Object{
    if ( $_.Name -eq "convert.ps1"){
        continue
    }
    Write-Host $_.Name
    $count++
	tshark -r $_.Name -T fields -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -E header=y > "change_$COUNT.csv"
    Import-Csv -Delimiter "`t" ".\change_$COUNT.csv" -Header ipsrc, ipdst, proto, tcpsrcport, tcpdstport, udpsrcport, udpdstport | Export-Csv "analysis_$COUNT.csv" -NoTypeInformation
    Remove-Item ".\change_$COUNT.csv"
    ##Remove-Item $_.Name
}
# Import-Csv -Delimiter "`t" .\analysis_1.csv -Header ipsrc, ipdst, proto, tcpsrcport, tcpdstport, udpsrcport, upddstport | Export-Csv analysis1new.csv