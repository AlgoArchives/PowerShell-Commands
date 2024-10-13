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