# Create new file for rules
New-Item localRules.ps1 | Out-Null -ErrorAction SilentlyContinue

Write-Host "Analyzing Local Traffic..."

# Import csv to analyze
$local = Import-Csv .\localTraffic.csv

# Get total number of lines, for percentages
$totalLocal = $local.Count

# Get Source and Destination IPs appearing in more than x% of packets
$srcAddr = ($local | Group-Object -Property ipsrc | Where-Object {($_.count/$totalLocal) -ge .01}).Name
$dstAddr = ($local | Group-Object -Property ipdst | Where-Object {($_.count/$totalLocal) -ge .01}).Name

$potentialRules = @()

ForEach ($row in $local){
    $Direction     = ""
    $Protocol      = ""
    $LocalPort     = ""
    $LocalAddress  = "192.168.0.20" # Local Address will not change
    $RemotePort    = ""
    $RemoteAddress = ""
    $Action        = "Allow" # All these rules will be Allow rules

    # If Inbound
    If ($row.ipdst -like "192.168.0.20"){
        $Direction = "Inbound"

        # If TCP
        If ($row.proto -eq 6){
            $Protocol = "TCP"
            If($srcAddr -contains $row.ipsrc){
                $LocalPort     = $row.tcpdstport
                $RemotePort    = $row.tcpsrcport
                $RemoteAddress = $row.ipsrc

                # Coming from Ephemeral Port
                If ($row.tcpsrcport -ge 1024){
                    $RemotePort = "Any"
                }

                # Going to Ephemeral Port
                If ($row.tcpdstport -ge 1024){
                    $LocalPort = "Any"
                }
            }
        }

        # If UDP
        ElseIf ($row.proto -eq 17){
            $Protocol = "UDP"
            If($srcAddr -contains $row.ipsrc){
                $LocalPort     = $row.udpdstport
                $RemotePort    = $row.udpsrcport
                $RemoteAddress = $row.ipsrc

                # Coming from Ephemeral Port
                If ($row.udpsrcport -ge 1024){
                    $RemotePort = "Any"
                }

                # Going to Ephemeral Port
                If ($row.udpdstport -ge 1024){
                    $LocalPort = "Any"
                }
            }
        }
    }

    # If Outbound
    ElseIf ($row.ipsrc -like "192.168.0.20"){
        $Direction = "Outbound"

        # If TCP
        If ($row.proto -eq 6){
            $Protocol = "TCP"
            If($dstAddr -contains $row.ipdst){
                $LocalPort     = $row.tcpsrcport
                $RemotePort    = $row.tcpdstport
                $RemoteAddress = $row.ipdst

                # Outbound from Ephemeral Port 
                If ($row.tcpsrcport -ge 1024){
                    $LocalPort = "Any"
                }

                # Outbound to Ephemeral Port
                If ($row.tcpdstport -ge 1024){
                    $RemotePort = "Any"
                }            
            }
        }

        # If UDP
        ElseIf ($row.proto -eq 17){
            $Protocol = "UDP"
            If($dstAddr -contains $row.ipdst){
                $LocalPort     = $row.udpsrcport
                $RemotePort    = $row.udpdstport
                $RemoteAddress = $row.ipdst

                # Outbound from Ephemeral Port 
                If ($row.udpsrcport -ge 1024){
                    $LocalPort = "Any"
                }

                # Outbound to Ephemeral Port
                If ($row.udpdstport -ge 1024){
                    $RemotePort = "Any"
                }
            }
        } 
    }

    # Only write to potential rule if all fields are filled out 
    If (($Direction -ne "") -and ($Protocol -ne "") -and ($LocalPort -ne "") -and ($RemotePort -ne "") -and ($RemoteAddress -ne "")){
        $rule = "New-NetFirewallRule -Direction $Direction -Protocol $Protocol -LocalPort $LocalPort -LocalAddress $LocalAddress -RemotePort $RemotePort -RemoteAddress $RemoteAddress -Action $Action"
        
        # Only Write to potentialRules if the rule is not in the array already
        If ($potentialRules -notcontains $rule){
            $potentialRules += $rule
        }
    }
}
$count = 1
ForEach ($potential in $potentialRules){
    $potential += " -DisplayName 'Local Rule #$count'"
    # Write-Host $potential
    Add-Content .\localRules.ps1 -Value $potential -PassThru
    $count++
}

# New-NetFirewallRule -Direction -Protocol -LocalPort -LocalAddress -RemotePort -RemoteAddress -Action