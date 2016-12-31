# SQL 2012 Default Instance
New-NetFirewallRule -DisplayName "SQL Server Database Engine instance MSSQLSERVER" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1433 -Program "%ProgramFiles%\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Binn\sqlservr.exe"
# SQL 2014 Default Instance
New-NetFirewallRule -DisplayName "SQL Server Database Engine instance MSSQLSERVER" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1433 -Program "%ProgramFiles%\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQL\Binn\sqlservr.exe"

New-NetFirewallRule -DisplayName "SQL Server Browser" -Direction inbound -Action Allow -Program "C:\Program Files (x86)\Microsoft SQL Server\90\Shared\sqlbrowser.exe"
New-NetFirewallRule -DisplayName "SQL Server Admin Connection" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1434
New-NetFirewallRule -DisplayName "SQL Server Named Pipes" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445

#New-NetFirewallRule -DisplayName "SQL Server Analysis Services instance MSSQLServerOLAPService" -Direction inbound –LocalPort 2383 -Protocol TCP -Action Allow

New-NetFirewallRule -DisplayName "SQL Server Reporting Services 80" -Direction inbound –LocalPort 80 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "SQL Server Reporting Services 443" -Direction inbound –LocalPort 443 -Protocol TCP -Action Allow

