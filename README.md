# PowerShell-Commands

### 1. **File and Folder Operations**

#### List Files and Directories
```powershell
Get-ChildItem -Path "C:\Path\To\Directory"
```

#### Create a New File
```powershell
New-Item -Path "C:\Path\To\File.txt" -ItemType File
```

#### Create a New Folder
```powershell
New-Item -Path "C:\Path\To\NewFolder" -ItemType Directory
```

#### Copy a File
```powershell
Copy-Item -Path "C:\Path\To\Source\File.txt" -Destination "C:\Path\To\Destination\"
```

#### Move a File
```powershell
Move-Item -Path "C:\Path\To\Source\File.txt" -Destination "C:\Path\To\Destination\"
```

#### Remove a File
```powershell
Remove-Item -Path "C:\Path\To\File.txt"
```

#### Remove a Folder
```powershell
Remove-Item -Path "C:\Path\To\Folder" -Recurse
```

#### Get File or Folder Properties
```powershell
Get-Item -Path "C:\Path\To\FileOrFolder" | Select-Object *
```

#### Get Directory Size
```powershell
Get-ChildItem -Path "C:\Path\To\Directory" -Recurse | Measure-Object -Property Length -Sum
```

---

### 2. **System Information**

#### Get System Information
```powershell
Get-ComputerInfo
```

#### Get Operating System Information
```powershell
Get-WmiObject -Class Win32_OperatingSystem
```

#### Get Installed Hotfixes
```powershell
Get-HotFix
```

#### Get List of Installed Programs
```powershell
Get-WmiObject -Class Win32_Product
```

#### Get CPU Information
```powershell
Get-WmiObject -Class Win32_Processor
```

#### Get Memory (RAM) Information
```powershell
Get-WmiObject -Class Win32_PhysicalMemory
```

#### Get Disk Space Information
```powershell
Get-PSDrive -PSProvider FileSystem
```

#### Check if a Service is Running
```powershell
Get-Service -Name "ServiceName"
```

#### Get Startup Programs
```powershell
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, User
```

---

### 3. **Networking**

#### Get IP Configuration
```powershell
Get-NetIPAddress
```

#### Get Active Network Adapters
```powershell
Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}
```

#### Test Network Connection (Ping)
```powershell
Test-Connection -ComputerName "google.com"
```

#### Get Open Ports
```powershell
Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" }
```

#### Get DNS Servers
```powershell
Get-DnsClientServerAddress
```

#### Get Network Interface Details
```powershell
Get-NetIPConfiguration
```

#### Get Routing Table
```powershell
Get-NetRoute
```

#### Disable a Network Adapter
```powershell
Disable-NetAdapter -Name "Ethernet"
```

#### Enable a Network Adapter
```powershell
Enable-NetAdapter -Name "Ethernet"
```

---

### 4. **Process Management**

#### Get Running Processes
```powershell
Get-Process
```

#### Stop a Process by Name
```powershell
Stop-Process -Name "ProcessName"
```

#### Start a Process
```powershell
Start-Process -FilePath "C:\Path\To\Program.exe"
```

#### Get Process by ID
```powershell
Get-Process -Id 1234
```

#### Get Process with High CPU Usage
```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
```

#### Kill a Process by ID
```powershell
Stop-Process -Id 1234
```

---

### 5. **User and System Management**

#### Create a New Local User
```powershell
New-LocalUser "Username" -Password (ConvertTo-SecureString "Password" -AsPlainText -Force) -FullName "Full Name" -Description "User Description"
```

#### Add a User to a Group
```powershell
Add-LocalGroupMember -Group "Administrators" -Member "Username"
```

#### List Local Users
```powershell
Get-LocalUser
```

#### List Local Groups
```powershell
Get-LocalGroup
```

#### Disable a Local User Account
```powershell
Disable-LocalUser -Name "Username"
```

#### Enable a Local User Account
```powershell
Enable-LocalUser -Name "Username"
```

---

### 6. **Windows Services**

#### List All Services
```powershell
Get-Service
```

#### Start a Service
```powershell
Start-Service -Name "ServiceName"
```

#### Stop a Service
```powershell
Stop-Service -Name "ServiceName"
```

#### Restart a Service
```powershell
Restart-Service -Name "ServiceName"
```

#### Get Service Status
```powershell
Get-Service -Name "ServiceName"
```

#### Set a Service to Start Automatically
```powershell
Set-Service -Name "ServiceName" -StartupType Automatic
```

---

### 7. **PowerShell Session and Environment**

#### Start Remote Session
```powershell
Enter-PSSession -ComputerName "RemoteComputerName"
```

#### Exit Remote Session
```powershell
Exit-PSSession
```

#### Execute Command on Remote Computer
```powershell
Invoke-Command -ComputerName "RemoteComputerName" -ScriptBlock { Get-Process }
```

#### List Environment Variables
```powershell
Get-ChildItem Env:
```

#### Set an Environment Variable
```powershell
[System.Environment]::SetEnvironmentVariable("VariableName", "VariableValue", "User")
```

---

### 8. **Scripting and Automation**

#### Create a PowerShell Script
```powershell
# Save this in a file with the extension .ps1
Write-Output "Hello, World!"
```

#### Execute a PowerShell Script
```powershell
.\script.ps1
```

#### Schedule a Task (using Task Scheduler)
```powershell
schtasks /create /tn "TaskName" /tr "C:\Path\To\script.ps1" /sc daily /st 09:00
```

#### Run a Script with Administrator Privileges
```powershell
Start-Process powershell.exe -ArgumentList "Start-Process -Verb RunAs 'C:\Path\To\script.ps1'"
```

---

### 9. **Windows Updates**

#### Check for Updates
```powershell
Install-Module PSWindowsUpdate
Get-WindowsUpdate
```

#### Install Updates
```powershell
Install-WindowsUpdate -AcceptAll
```

#### Hide a Windows Update
```powershell
Hide-WindowsUpdate -KBArticleID "KB1234567"
```

---

### 10. **Miscellaneous Commands**

#### Generate a Random Password
```powershell
[System.Web.Security.Membership]::GeneratePassword(12, 2)
```

#### Get PowerShell Version
```powershell
$PSVersionTable.PSVersion
```

#### Clear PowerShell Console
```powershell
Clear-Host
```

#### Export Output to CSV
```powershell
Get-Process | Export-Csv -Path "C:\Path\To\Output.csv" -NoTypeInformation
```

---

### 11. **Help and Documentation**

#### Get Help for a Command
```powershell
Get-Help Get-Process
```

#### Update Help Files
```powershell
Update-Help
```

---

### 12. **Development and Debugging**

#### Get Installed Modules
```powershell
Get-Module -ListAvailable
```

#### Import a Module
```powershell
Import-Module "ModuleName"
```

#### Find a Module from the PowerShell Gallery
```powershell
Find-Module -Name "ModuleName"
```

#### Install a Module from PowerShell Gallery
```powershell
Install-Module -Name "ModuleName"
```

#### Remove a Module
```powershell
Remove-Module -Name "ModuleName"
```

#### Export a Module Member
```powershell
Export-ModuleMember -Function "FunctionName" -Alias "AliasName"
```

---

### 13. **Version Control (Git) with PowerShell**

#### Clone a Git Repository
```powershell
git clone https://github.com/username/repo.git
```

#### Check Git Status
```powershell
git status
```

#### Stage Files for Commit
```powershell
git add .
```

#### Commit Changes
```powershell
git commit -m "Your commit message"
```

#### Push Changes to Remote Repository
```powershell
git push origin main
```

#### Pull Latest Changes
```powershell
git pull origin main
```

#### Create a New Branch
```powershell
git checkout -b "new-branch-name"
```

#### Merge a Branch
```powershell
git merge "branch-name"
```

---

### 14. **Security and Encryption**

#### Encrypt a Password
```powershell
$SecurePassword = Read-Host -AsSecureString
```

#### Convert Secure Password to Plain Text (for Testing Only!)
```powershell
[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))
```

#### Convert a String to a Secure String
```powershell
$SecureString = ConvertTo-SecureString "yourpassword" -AsPlainText -Force
```

#### Create Self-Signed Certificate
```powershell
New-SelfSignedCertificate -DnsName "www.example.com" -CertStoreLocation "cert:\LocalMachine\My"
```

#### Add a Trusted Root Certificate Authority
```powershell
Import-Certificate -FilePath "C:\Path\To\Certificate.cer" -CertStoreLocation Cert:\LocalMachine\Root
```

---

### 15. **Error Handling and Debugging**

#### Try/Catch Block for Error Handling
```powershell
try {
    # Code that might throw an exception
    $result = Get-Process -Name "NonExistentProcess"
} catch {
    Write-Host "Error occurred: $_"
}
```

#### Display Errors in PowerShell
```powershell
$Error
```

#### Clear Error Buffer
```powershell
$Error.Clear()
```

#### Set Error Action Preference to Stop
```powershell
$ErrorActionPreference = "Stop"
```

#### Check Last Error
```powershell
$?
```

---

### 16. **Working with APIs**

#### Invoke a REST API (GET Request)
```powershell
Invoke-RestMethod -Uri "https://api.example.com/data" -Method Get
```

#### Send POST Request to API
```powershell
Invoke-RestMethod -Uri "https://api.example.com/data" -Method Post -Body $jsonBody -ContentType "application/json"
```

#### Convert JSON to PowerShell Object
```powershell
$json = '{"name": "John", "age": 30}'
ConvertFrom-Json $json
```

#### Convert PowerShell Object to JSON
```powershell
$object = @{ name = "John"; age = 30 }
$object | ConvertTo-Json
```

---

### 17. **Performance Monitoring**

#### Get CPU Usage
```powershell
Get-WmiObject -Class Win32_Processor | Select-Object -Property LoadPercentage
```

#### Get Memory Usage
```powershell
Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property TotalVisibleMemorySize, FreePhysicalMemory
```

#### Monitor Disk Performance
```powershell
Get-Counter -Counter "\PhysicalDisk(_Total)\% Disk Time"
```

#### Monitor Network Interface Throughput
```powershell
Get-Counter -Counter "\Network Interface(*)\Bytes Total/sec"
```

#### Measure Script Execution Time
```powershell
Measure-Command { # Your script block here }
```

---

### 18. **Database Management (SQL)**

#### Execute SQL Query (using SQL Server)
```powershell
Invoke-Sqlcmd -Query "SELECT * FROM YourTable" -ServerInstance "ServerName" -Database "DatabaseName"
```

#### Export SQL Query Results to CSV
```powershell
Invoke-Sqlcmd -Query "SELECT * FROM YourTable" -ServerInstance "ServerName" -Database "DatabaseName" | Export-Csv -Path "C:\Path\To\Export.csv" -NoTypeInformation
```

#### Backup a SQL Database
```powershell
Backup-SqlDatabase -ServerInstance "ServerName" -Database "DatabaseName" -BackupFile "C:\Path\To\Backup.bak"
```

#### Restore a SQL Database
```powershell
Restore-SqlDatabase -ServerInstance "ServerName" -Database "DatabaseName" -BackupFile "C:\Path\To\Backup.bak"
```

---

### 19. **File Compression and Archiving**

#### Compress Files into a Zip Archive
```powershell
Compress-Archive -Path "C:\Path\To\Files\*" -DestinationPath "C:\Path\To\Archive.zip"
```

#### Extract a Zip Archive
```powershell
Expand-Archive -Path "C:\Path\To\Archive.zip" -DestinationPath "C:\Path\To\ExtractedFiles"
```

---

### 20. **Working with Active Directory (Requires Active Directory Module)**

#### Import Active Directory Module
```powershell
Import-Module ActiveDirectory
```

#### Get AD Users
```powershell
Get-ADUser -Filter *
```

#### Get AD Groups
```powershell
Get-ADGroup -Filter *
```

#### Add User to Active Directory
```powershell
New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@example.com" -Path "OU=Users,DC=example,DC=com" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
```

#### Remove AD User
```powershell
Remove-ADUser -Identity "jdoe"
```

#### Find Locked AD Accounts
```powershell
Search-ADAccount -LockedOut
```

---

### 21. **Task Automation and Scheduling**

#### Create a Scheduled Task
```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "C:\Path\To\YourScript.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MyScheduledTask" -Description "Runs a PowerShell script daily at 9 AM"
```

#### Remove a Scheduled Task
```powershell
Unregister-ScheduledTask -TaskName "MyScheduledTask" -Confirm:$false
```

---

### 22. **Containers (Docker)**

#### List Docker Containers
```powershell
docker ps
```

#### Start a Docker Container
```powershell
docker start "ContainerNameOrID"
```

#### Stop a Docker Container
```powershell
docker stop "ContainerNameOrID"
```

#### Remove a Docker Container
```powershell
docker rm "ContainerNameOrID"
```

#### Pull a Docker Image
```powershell
docker pull "ImageName"
```

---

### 23. **PowerShell Remoting**

#### Enable PowerShell Remoting
```powershell
Enable-PSRemoting -Force
```

#### Establish Remote Session
```powershell
Enter-PSSession -ComputerName "RemoteComputerName"
```

#### Run Command on Remote Machine
```powershell
Invoke-Command -ComputerName "RemoteComputerName" -ScriptBlock { Get-Process }
```

#### Disable PowerShell Remoting
```powershell
Disable-PSRemoting -Force
```

### Acknowledgment

Some of the PowerShell commands in this repository have been inspired by or sourced from the excellent article "[Top 51 PowerShell Commands That You Should Know](https://stackify.com/powershell-commands-every-developer-should-know/)" by **Stackify**. This article provides a comprehensive guide for developers and IT professionals to use PowerShell for various administrative and development tasks.