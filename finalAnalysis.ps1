.\localAnalysis.ps1

$local = Read-Host "Do you want to apply the Local rules?[y/n] "
If ($local -like "y"){
    .\localRules.ps1
}


.\remoteAnalysis.ps1
$remote = Read-Host "Do you want to apply the Remote rules?[y/n] "
If ($remote -like "y"){
    .\remoteRules.ps1
}
