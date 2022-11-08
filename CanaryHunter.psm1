# Print the welcome message
$manifest = Import-PowerShellDataFile "$PSScriptRoot\CanaryHunter.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle="CanaryHunter $version"

$banner=@"
   _____          _   _          _______     __  _    _ _    _ _   _ _______ ______ _____  
  / ____|   /\   | \ | |   /\   |  __ \ \   / / | |  | | |  | | \ | |__   __|  ____|  __ \ 
 | |       /  \  |  \| |  /  \  | |__) \ \_/ /  | |__| | |  | |  \| |  | |  | |__  | |__) |
 | |      / /\ \ | . `  | / /\ \ |  _  / \   /   |  __  | |  | |  . ` |  | |  |  __| |  _  / 
 | |____ / ____ \| |\  |/ ____ \| | \ \  | |    | |  | | |__| | |\  |  | |  | |____| | \ \ 
  \_____/_/    \_\_| \_/_/    \_\_|  \_\ |_|    |_|  |_|\____/|_| \_|  |_|  |______|_|  \_\
                                                                                           
                                                                                           
 by @C0axx (Curtis Ringwald)

"@
Write-Host $banner -ForegroundColor Red

# Load the .ps1 scripts
$scripts = @(Get-ChildItem -Path $PSScriptRoot\modules\*.ps1 -ErrorAction SilentlyContinue)
$c = 0
foreach ($script in $scripts) {
    Write-Progress -Activity "Importing script" -Status $script -PercentComplete (($c++/$scripts.count)*100) 
    try {
        . $script.FullName
    } catch {
        Write-Error "Failed to import $($script.FullName): $_"
    }
}
# Export functions
$functions=@(
    # CanaryHunter.ps1
    "Invoke-DocxCheck"
    "Invoke-XlsxCheck"
    "Invoke-PDFCheck"
    "Invoke-RegistryCheck"
    "Invoke-AWSCheck"
    "Invoke-WireguardCheck"
    "Invoke-KubeCheck"
    "Invoke-MySqlDumpCheck"
)
$c = 0
foreach($function in $functions)
{
    Write-Progress -Activity "Exporting function" -Status $function -PercentComplete (($c++/$functions.count)*100)
    Export-ModuleMember -Function $function
}
