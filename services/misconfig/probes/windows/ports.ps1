$ports = Get-NetTCPConnection -State Listen | Select-Object `
    LocalAddress,
    LocalPort,
    OwningProcess

$services = foreach ($p in $ports) {
    $proc = Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Address = $p.LocalAddress
        Port    = $p.LocalPort
        Process = $proc.ProcessName
        PID     = $p.OwningProcess
    }
}

$firewall = Get-NetFirewallProfile | Select Name, Enabled
$admins   = Get-LocalGroupMember Administrators | Select Name
$netifs   = Get-NetIPAddress | Select InterfaceAlias, IPAddress

$result = @{
    ports     = $services
    firewall  = $firewall
    admins    = $admins
    networks  = $netifs
}

$result | ConvertTo-Json -Depth 5
