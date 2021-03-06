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
      [Parameter(Mandatory = $true)]
      [string]$Audit,
      [int]$Low,
      [int]$Moderate,
      [int]$High,
      [int]$Critical
   )

   $noVulnerabilities = $Audit | Select-String -Pattern "found 0 vulnerabilities"
   If ($noVulnerabilities.Matches.Success -eq $true) {
      return $false
   }

   if ($PSBoundParameters.ContainsKey("Low") -eq $false -and $PSBoundParameters.ContainsKey("Moderate") -eq $false -and $PSBoundParameters.ContainsKey("High") -eq $false -and $PSBoundParameters.ContainsKey("Critical") -eq $false) {
      return $true
   }

   function CheckByLevel {
      param (
         [string] $Level,
         [int] $MaxCount
      )
      $lowVulnerabilities = $auditResult | Select-String -Pattern "(\d+) $Level"
      Write-Output $lowVulnerabilities
      if ($lowVulnerabilities.Matches.Success -and [int]$lowVulnerabilities.Matches.Groups[1].Value -gt $MaxCount) {
         return $true
      }
      return $false   
   }
   
   if ($PSBoundParameters.ContainsKey("Low") -and (CheckByLevel "low" $Low) -eq $true) { return $true }

   if ($PSBoundParameters.ContainsKey("Moderate") -and (CheckByLevel "moderate" $Moderate) -eq $true) { return $true }

   if ($PSBoundParameters.ContainsKey("High") -and (CheckByLevel "high" $High) -eq $true) { return $true }

   if ($PSBoundParameters.ContainsKey("Critical") -and (CheckByLevel "critical" $Critical) -eq $true) { return $true }

   return $false
}