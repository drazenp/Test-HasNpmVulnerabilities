function Test-HasNpmVulnerabilities {
   <#
.SYNOPSIS
    Returns a list of services that are set to start automatically, are not
    currently running, excluding the services that are set to delayed start.

.DESCRIPTION
    Get-MrAutoStoppedService is a function that returns a list of services from
    the specified remote computer(s) that are set to start automatically, are not
    currently running, and it excludes the services that are set to start automatically
    with a delayed startup.

.PARAMETER ComputerName
    The remote computer(s) to check the status of the services on.

.PARAMETER Credential
    Specifies a user account that has permission to perform this action. The default
    is the current user.

.EXAMPLE
     Get-MrAutoStoppedService -ComputerName 'Server1', 'Server2'

.EXAMPLE
     'Server1', 'Server2' | Get-MrAutoStoppedService

.EXAMPLE
     Get-MrAutoStoppedService -ComputerName 'Server1' -Credential (Get-Credential)
#>

   param (
      [Parameter(Mandatory)]
      [string]$Audit,
      [int]$Low,
      [int]$Moderate,
      [int]$High,
      [int]$Critical
   )

   $noVulnerabilities = $Audit | Select-String -Pattern 'found 0 vulnerabilities'
   If ($noVulnerabilities.Matches.Success -eq $true) {
      return $false
   }

   if ($PSBoundParameters.ContainsKey('Low') -eq $false -and $PSBoundParameters.ContainsKey('Moderate') -eq $false -and $PSBoundParameters.ContainsKey('High') -eq $false -and $PSBoundParameters.ContainsKey('Critical') -eq $false) {
      return $true
   }

   if ($PSBoundParameters.ContainsKey('Low')) {
      $lowVulnerabilities = $auditResult | Select-String -Pattern "(\d+) low"
      if ($lowVulnerabilities.Matches.Success -and [int]$lowVulnerabilities.Matches.Groups[1].Value -gt $Low) {
         return $true
      }
   }

   if ($PSBoundParameters.ContainsKey('Moderate')) {
      $moderateVulnerabilities = $auditResult | Select-String -Pattern "(\d+) moderate"
      if ($moderateVulnerabilities.Matches.Success -and [int]$moderateVulnerabilities.Matches.Groups[1].Value -gt $Moderate) {
         return $true
      }
   }

   if ($PSBoundParameters.ContainsKey('High')) {
      $highVulnerabilities = $auditResult | Select-String -Pattern "(\d+) high"
      if ($highVulnerabilities.Matches.Success -and [int]$highVulnerabilities.Matches.Groups[1].Value -gt $High) {
         return $true
      }
   }

   if ($PSBoundParameters.ContainsKey('Critical')) {
      $criticalVulnerabilities = $auditResult | Select-String -Pattern "(\d+) critical"
      if ($criticalVulnerabilities.Matches.Success -and [int]$criticalVulnerabilities.Matches.Groups[1].Value -gt $Critical) {
         return $true
      }
   }

   return $false
}