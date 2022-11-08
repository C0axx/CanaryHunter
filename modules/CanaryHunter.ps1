function Invoke-DocxCheck ()
{
<#
    .SYNOPSIS
        Helper to Return Any Canary Token Within Docx Files.
        Copies to docx to zip then parses xml content for Regex containing Canary Token Domains.
        
    .EXAMPLE
        PS C:\> Invoke-DocxCheck -DocxPath .\gwfrr71nre84bk5gobf3h96ms.docx
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$DocxPath,
		[String]$tempPath = $ENV:TEMP
	)
	Copy-Item -Path $DocxPath -Destination $tempPath/Doc.zip -ErrorAction SilentlyContinue
	Expand-Archive -Path $tempPath/Doc.zip -DestinationPath $tempPath/TempDoc -ErrorAction SilentlyContinue
	$DocxFiles = Get-ChildItem -Path $tempPath/TempDoc -Filter *.xml -Recurse -ErrorAction SilentlyContinue -Force
	$canaryFound = $false
	$regex = '([a-zA-Z]{3,})://(.+\.)?canarytokens\.com+(/[\w- ./?%&=]*)|([a-zA-Z]{3,})://internalcanarytokendomain\.org+(/[\w- ./?%&=]*)'
	$DocxFiles | ForEach-Object {
		IF ($_.FullName -match "footer" -or $_.FullName -match "header")
		{
			IF ($match = Select-String -Path $_.FullName -Pattern $regex -AllMatches)
			{
				Write-Host -ForegroundColor Red "Url Found:"
				$OFS = "`r"
				$OFS
				$match | Select-String -Pattern 'canarytoken' | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
			}
		}
	}
	Remove-Item -Path $tempPath/Doc.zip -Force
	Remove-Item -Path $tempPath/TempDoc -Recurse -Force
}

function Invoke-XlsxCheck ()
{
<#
    .SYNOPSIS
        Helper to Return Any Canary Token Within Xlsx Files.
        Copies to xlsx to zip then parses xml.rels content for Regex containing Canary Token Domains.
        
    .EXAMPLE
        PS C:\>  Check-Xlsx -XlsxPath .\gwfrr71nre84bk5gobf3h96ms.xlsx
#>
	
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$XlsxPath,
		[String]$tempPath = $env:TEMP
	)
	Copy-Item -Path $XlsxPath -Destination $tempPath/Xlsx.zip -ErrorAction SilentlyContinue
	Expand-Archive -Path $tempPath/Xlsx.zip -DestinationPath $tempPath/TempXlsx -ErrorAction SilentlyContinue
	$OFS = "`r"
	$XlsxFiles = Get-ChildItem -Path $tempPath/TempXlsx -Filter *.xml.rels -Recurse -ErrorAction SilentlyContinue -Force
	$regex = '([a-zA-Z]{3,})://(.+\.)?canarytokens\.com+(/[\w- ./?%&=]*)|([a-zA-Z]{3,})://internalcanarytokendomain\.org+(/[\w- ./?%&=]*)'
	
	$XlsxFiles | ForEach-Object {
		IF ($match = Select-String -Path $_.FullName -Pattern $regex -AllMatches)
		{
			Write-Host -ForegroundColor Red "Url Found:"
			$OFS
			$match | Select-String -Pattern 'canarytoken' | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
		}
	}
	Remove-Item -Path $tempPath/Xlsx.zip -Force
	Remove-Item -Path $tempPath/TempXlsx -Recurse -Force
}

function Invoke-PDFCheck ()
{
<#
    .SYNOPSIS
        Helper to Return Any Canary Token Within PDF Files.
        Executes https://github.com/dzzie/pdfstreamdumper against specified .pdf then parse .unk stream files for keyword Canary.
        
    .EXAMPLE
        PS C:\> Invoke-PDFCheck -StreamDumperPath C:\PDFStreamDumper\PDFStreamDumper.exe -pdfPath .\gwfrr71nre84bk5gobf3h96ms.pdf
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$PDFPath,
		[Parameter(Mandatory = $True)]
		[String]$StreamDumperPath,
		[String]$tempPath = $env:TEMP
	)
	Copy-Item -Path $PDFPath -Destination $tempPath/temp.pdf -ErrorAction SilentlyContinue
	New-Item -Path "$tempPath/Streams" -ItemType Directory | Out-Null
	& $StreamDumperPath $tempPath/temp.pdf /extract "$tempPath/Streams/"
	Start-Sleep 2
	$OFS = "`r"
	$output = Get-ChildItem -Path $tempPath/Streams -Filter *.unk -Recurse -ErrorAction SilentlyContinue -Force | Get-Content -Delimiter '(' | Select-String -Pattern canarytoken -AllMatches
	Write-Host -ForegroundColor Red "Url Found:"
	$OFS
	$output.Line
	
	Remove-Item -Path $tempPath/temp.pdf -Force
	Remove-Item -Path $tempPath/Streams -Recurse -Force
}

function Invoke-RegistryCheck ()
{
<#
    .SYNOPSIS
        Helper to Return Any Canary Tokens Found Within the "SilentProcessExit" Windows Registry Location.
        By default checks "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" for a process using silent exit monitoring, then runs regex against the Monitor Process Property.
        
    .EXAMPLE
        PS C:\> Invoke-RegistryCheck -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\"
#>
	[CmdletBinding()]
	Param (
		[String]$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\"
	)
	$OFS = "`r"
	$Executable = Get-ChildItem -path $RegistryPath -rec -ea SilentlyContinue | Select-Object Name
	Write-Host -ForegroundColor Red "Sensitive Command Canary Found For:"
	$Executable.Name
	$OFS
	$Registry = Get-ChildItem -path $RegistryPath -rec -ea SilentlyContinue | Get-ItemProperty -Name MonitorProcess | select -Property MonitorProcess | Select-Object -Property MonitorProcess -ExpandProperty MonitorProcess
	$regex = '\.([A-Za-z0-9]+(\.[A-Za-z0-9]+)+)'
	$OFS
	Write-Host -ForegroundColor Red "Monitor Process Canary Value Found:"
	$Registry
	$OFS
}

function Invoke-AWSCheck ()
{
<#
    .SYNOPSIS
        Helper to Return Any Canary Tokens Within AWS Configs.
        Scans AWS access keys that may belong to the AWS account from the free Canary token service based on Bobby Lin's Blog.
        
    .EXAMPLE
        PS C:\> Invoke-AWSCheck -AWSPath AWSconfig
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$AWSPath
	)
	IF ($match = Select-String -Path $AWSPath -Pattern "AKIAYVP4CIPP")
	{
		Write-Host -ForegroundColor Red "Possible Canary Config Found:"
		$OFS = "`r"
		$OFS
		$match
	}
}

function Invoke-WireguardCheck ()
{
<#
    .SYNOPSIS
        Helper to Return Any Canary Tokens Within WireGuard Configs.
        Scans WireGuard configs for known Canary Token IP addresses.
        
    .EXAMPLE
        PS C:\> Invoke-WireguardCheck -WireGuardPath WireGuard.config
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$WireGuardPath
	)
	$Endpoints = '52.18.63.80', '52.18.63.80', '52.18.63.80', '205.251.196.97', '205.251.198.164', '205.251.193.123', '205.251.195.174', '172.253.63.26', '142.250.27.26', '142.250.153.27', '209.85.202.26', '64.233.184.27', '54.155.229.124', '52.204.60.219', '52.204.60.219', '52.204.60.219', '18.206.31.94', '18.206.31.94', '18.206.31.94', '52.31.39.52', '52.31.39.52', '52.31.39.52', '52.45.123.26', '52.45.123.26', '52.45.123.26', '52.31.39.52', '205.251.197.152', '205.251.199.151', '205.251.193.232', '205.251.194.96'
	IF ($match = Select-String -Path $WireGuardPath -Pattern $Endpoints | Out-String)
	{
		Write-Host -ForegroundColor Red "Possible Canary Config Found:"
		$OFS = "`r"
		$OFS
		$match.Split(":")[2]
	}
}

function Invoke-KubeCheck ()
{
<#
    .SYNOPSIS
        Helper to Return Any Canary Tokens Within Kube Configs.
        Scans Kube configs for known Canary Token IP addresses.
        
    .EXAMPLE
        PS C:\> Invoke-KubeCheck -KubeConfigPath Kube.config
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$KubeConfigPath
	)
	$Endpoints = '52.18.63.80', '52.18.63.80', '52.18.63.80', '205.251.196.97', '205.251.198.164', '205.251.193.123', '205.251.195.174', '172.253.63.26', '142.250.27.26', '142.250.153.27', '209.85.202.26', '64.233.184.27', '54.155.229.124', '52.204.60.219', '52.204.60.219', '52.204.60.219', '18.206.31.94', '18.206.31.94', '18.206.31.94', '52.31.39.52', '52.31.39.52', '52.31.39.52', '52.45.123.26', '52.45.123.26', '52.45.123.26', '52.31.39.52', '205.251.197.152', '205.251.199.151', '205.251.193.232', '205.251.194.96'
	$regex = "[A-Za-z0-9]+: https:\/\/\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b:[A-Za-z0-9]+"
	$OFS = "`r"
	IF ($match = Select-String -Path $KubeConfigPath -Pattern $Endpoints | Out-String)
	{
		Write-Host -ForegroundColor Red "Possible Canary Config Found:"
		$OFS
		$match | Select-String -Pattern $Regex -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
	}
}

function Invoke-MySqlDumpCheck ()
{
<#
    .SYNOPSIS
        Helper to Return Any Canary Tokens Within MySQL Dumps.
        Scans MYSQL dumps for SET @b= then runs regex to determine if MASTER HOST contains known Canary Token IP addresses.
        
    .EXAMPLE
        PS C:\> Invoke-MySqlDumpCheck -MySQLDumpPath Dump.sql
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)]
		[String]$MySQLDumpPath
	)
	$content = Get-Content $MySQLDumpPath | Select-string -Pattern "SET @b =" | Out-String
	$Decoded = $content.Split("'")[1] | ForEach-Object { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_)) }
	$OFS = "`r"
	$Regex = "MASTER_HOST='[A-Za-z0-9]+\.canarytokens\.[A-Za-z0-9]+'"
	IF ($match = $Decoded | Select-String -Pattern $Regex -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value })
	{
		Write-Host -ForegroundColor Red "Url Found:"
		$OFS
		$match
	}
}
