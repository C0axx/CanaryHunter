@{
# Script module or binary module file associated with this manifest.
RootModule = 'CanaryHunter.psm1'

# Version number of this module.
ModuleVersion = '0.0.1'

# Author of this module
Author = 'Curtis Ringwald - @C0axx'

# Description of the functionality provided by this module
Description = 'Canary Hunter aims to be a quick PowerShell script to check for Common Canaries in various formats generated for free on canarytokens.org'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = '*'

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        Tags = @('security','pentesting','red team','offense','canary','canary token')
        ProjectUri = 'https://github.com/C0axx/CanaryHunter'

    } # End of PSData hashtable

} # End of PrivateData hashtable

}

