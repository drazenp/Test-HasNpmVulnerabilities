function Test-HasNpmVulnerabilities {
   <#
   .SYNOPSIS
      Returns a flag indicating if npm packages have vulnerabilities based on criteria.

   .DESCRIPTION
      Test-HasNpmVulnerabilities is a function that analyses npm audit results and 
      checks if npm packages are vulnerable by comparing the number of vulnerabilities
      with a number of allowed vulnerabilities per level.

   .PARAMETER Audit
      The result of npm audit command.

   .PARAMETER Low
      Number of allowed low vulnerabilities. Not checked if not specified.

   .PARAMETER Moderate
      Number of allowed moderate vulnerabilities. Not checked if not specified.

   .PARAMETER High
      Number of allowed high vulnerabilities. Not checked if not specified.

   .PARAMETER Critical
      Number of allowed critical vulnerabilities. Not checked if not specified.

   .EXAMPLE
      Test-HasNpmVulnerabilities -Audit 'found 9 vulnerabilities (2 low, 6 high, 1 critical)' -Low 2 -High 6 -Critical 0
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