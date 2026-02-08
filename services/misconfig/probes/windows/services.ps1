Get-Service |
Where-Object {$_.Status -eq "Running"} |
Select Name, DisplayName, StartType |
ConvertTo-Json -Depth 2
