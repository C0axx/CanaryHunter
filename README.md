# Canary Hunter
<img src="https://github.com/C0axx/CanaryHunter/blob/main/Red_Canary.png" width="600">

### Summary
While executing multiple red team engagements over the past few years there have been multiple times where I have run up against Canary Tokens which could potentially alert the SOC to actions taken. As such I spent some time running down the rabbit hole discovering if there were ways to detect these canaries within files present within the environment. Canary Hunter was formed to quickly check for Common Canaries in various formats generated for free on canarytokens.org

### What are Canary Tokens
Canary tokens are a free, quick, painless way to help defenders discover they've been breached (by having attackers announce themselves.) For more information on what Canary tokens are and how to generate them for free you can check out 
https://blog.thinkst.com/p/canarytokensorg-quick-free-detection.html

### Overview
Currently the script can detect canaries in the following formats:
* Docx
* Xlsx
* PDF (With the caveat that [PDFStreamDumper](https://github.com/dzzie/pdfstreamdumper) is installed)
* Sensitive Command Tokens via Registry Entries
* AWS Configs
* WireGuard Configs
* Kube Config
* MySQL Dump Tokens

### Usage

#### Import Script
```
PS C:\> Import-Module .\CanaryHunter.psd1
```

#### Docx Files
Copies to docx to zip then parses xml content for Regex containing Canary Token Domains.
```
PS C:\> Invoke-DocxCheck -DocxPath gwfrr71nre84bk5gobf3h96ms.docx
Url Found:

http://canarytokens.com/feedback/traffic/gwfrr71nre84bk5gobf3h96ms/index.html
```
#### Xlsx Files
Copies to xlsx to zip then parses xml.rels content for Regex containing Canary Token Domains.
```
PS C:\> Invoke-XlsxCheck -XlsxPath  .\gwfrr71nre84bk5gobf3h96ms.xlsx
Url Found:

http://canarytokens.com/images/tags/articles/gwfrr71nre84bk5gobf3h96ms/contact.php
```

#### PDF Files
Executes [PDFStreamDumper](https://github.com/dzzie/pdfstreamdumper) against specified .pdf then parses .unk stream files for keyword Canary.
```
PS C:\> Invoke-PDFCheck -StreamDumperPath C:\PDFStreamDumper\PDFStreamDumper.exe -PDFPath .\gwfrr71nre84bk5gobf3h96ms.pdf
Url Found:

http://gwfrr71nre84bk5gobf3h96ms.canarytokens.net/RNGPLTCJSTEKJHOMLLYCQINNXOVOWCUVME
```

#### Registry Entries
By default checks "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" for a process using silent exit monitoring, then runs regex against the Monitor Process Property.
```
PS C:\> Invoke-RegistryCheck
Sensitive Command Canary Found For:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\net.exe


Monitor Process Canary Value Found:
cmd.exe /c start /min powershell.exe -windowstyle hidden -command "$($u=$(\"u$env:username\" 
-replace('[^\x00-\x7f]|\s', ''))[0..63] -join '';$c=$(\"c$env:computername\" -replace('[^\x00-\x7f]|\s', ''));
Resolve-DnsName -Name \"$c.UN.$u.CMD.gwfrr71nre84bk5gobf3h96ms.canarytokens.com\")"
```
#### AWS Configs
Scans AWS access keys that may belong to the AWS account from the free Canary token service based on Bobby Lin's Blog.
```
PS C:\> Invoke-AWSCheck -AWSPath .\AWS.config
Possible Canary Config Found:

AWS.config:2:aws_access_key_id = AKIAYVP4CIPPJUYTRES
```

#### WireGuard Configs
Scans WireGuard configs for known Canary Token IP addresses.
```
PS C:\> Invoke-WireguardCheck -WireGuardPath .\WireguardConfig
Possible Canary Config Found:

Endpoint = 52.18.63.80
```
#### Kube Configs
Scans Kube configs for known Canary Token IP addresses.
```
PS C:\> Invoke-KubeCheck -KubeConfigPath .\KubeConfig
Possible Canary Config Found:

server: https://52.18.63.80:6443
```
#### MySQL Dumps
Scans MYSQL dumps for SET @b= then runs regex to determine if MASTER HOST contains known Canary Token IP addresses.
```
PS C:\> Invoke-MySqlDumpCheck -MySQLDumpPath .\gwfrr71nre84bk5gobf3h96ms_mysql_dump.sql
Url Found:

MASTER_HOST='gwfrr71nre84bk5gobf3h96ms.canarytokens.com'
```

#### Block Canaries OutBound
Blocks known Canary IPs
```
PS C:\> Invoke-BlockCanaries

DisplayName                   : Block All Known Canary IP Addresses
Enabled                       : True
Profile                       : Any
Direction                     : Outbound
Action                        : Block

Firewall Rule to Block Canary IP Addresses Succesffully Created
```


### Acknowledgments
[HackingLZ](https://twitter.com/HackingLZ/) - [Coalmine.py](https://gist.github.com/HackingLZ/0285d248f648f5dd216758c3fbf78c97)

[Bobby Lin's Blog](https://onappsec.com/canary-token-is-great-but-beware-of-a-flaw-when-using-thinksts-free-service-for-canary-aws-token/)

[WatchfulSleeper](https://github.com/WatchfulSleeper) - [CanaryTokensDetectorForWin](https://github.com/WatchfulSleeper/CanaryTokensDetectorForWin)

[singe](https://twitter.com/singe) - [Canary Token Yara](https://gist.github.com/singe/0c334b514a9eed2792b88df1dfb766cc)
