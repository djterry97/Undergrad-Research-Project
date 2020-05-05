# Create new file for rules
New-Item remoteRules.ps1 | Out-Null -ErrorAction SilentlyContinue

Write-Host "Analyzing Remote Traffic..."

# Import csv to analyze
$remote = Import-Csv .\remoteTraffic.csv

# Get total number of lines, for percentages
$totalRemote = $remote.Count

### Because it is Remote Traffic, and the Remote IP addresses will constantly be changing,
### We cannot use source and destination IPs, so we are choosing to use Source and Destination Ports
# Get Source and Destination Ports appearing in more than x% of packets
$tcpSourcePort = ($remote | Group-Object -Property tcpsrcport | Where-Object {($_.count/$totalRemote) -ge .05}).Name
$tcpDestPort   = ($remote | Group-Object -Property tcpdstport | Where-Object {($_.count/$totalRemote) -ge .05}).Name
$udpSourcePort = ($remote | Group-Object -Property udpsrcport | Where-Object {($_.count/$totalRemote) -ge .05}).Name
$updDestPort   = ($remote | Group-Object -Property udpdstport | Where-Object {($_.count/$totalRemote) -ge .05}).Name

$potentialRules = @()

ForEach ($row in $remote){
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

        # If TCP Traffic
        If ($row.proto -eq 6){
            $Protocol = "TCP"
            If(($tcpSourcePort -contains $row.tcpsrcport) -or ($tcpDestPort -contains $row.tcpdstport)){
                $LocalPort     = $row.tcpdstport
                $RemotePort    = $row.tcpsrcport
                $RemoteAddress = "Any"

                # Coming From Ephemeral Port
                If ($row.tcpsrcport -ge 1024){
                    $RemotePort = "Any"
                }

                # Going to Ephemeral Port
                If ($row.tcpdstport -ge 1024){
                    $LocalPort = "Any"
                }
            }
        }

        ElseIf ($row.proto -eq 17){
            $Protocol = "UDP"
            If(($udpSourcePort -contains $row.udpsrcport) -or ($udpDestPort -contains $row.udpdstport)){
                $LocalPort     = $row.udpdstport
                $RemotePort    = $row.udpsrcport
                $RemoteAddress = "Any"

                # Coming From Ephemeral Port
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
            If(($tcpSourcePort -contains $row.tcpsrcport) -or ($tcpDestPort -contains $row.tcpdstport)){
                $LocalPort     = $row.tcpsrcport
                $RemotePort    = $row.tcpdstport
                $RemoteAddress = "Any"

                # Outbound From Ephemeral Port
                If ($row.tcpsrcport -ge 1024){
                    $RemotePort = "Any"
                }

                # Outbound to Ephemeral Port
                If ($row.tcpdstport -ge 1024){
                    $LocalPort = "Any"
                }                
            }
        }

        # If UDP
        ElseIf ($row.proto -eq 17){
            $Protocol = "UDP"
            If(($udpSourcePort -contains $row.udpsrcport) -or ($udpDestPort -contains $row.udpdstport)){
                $LocalPort     = $row.udpsrcport
                $RemotePort    = $row.udpdstport
                $RemoteAddress = "Any"

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
    $potential += " -DisplayName 'Remote Rule #$count'"
    # Write-Host $potential
    Add-Content .\remoteRules.ps1 -Value $potential -PassThru
    $count++
}