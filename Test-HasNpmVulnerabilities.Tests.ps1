BeforeAll { 
   . $PSScriptRoot/Test-HasNpmVulnerabilities.ps1
}

Describe 'Test-HasNpmVulnerabilities' {
   It 'Returns $false for 0 vulnerabilities' {
      $auditResult = "
                       === npm audit security report ===                        

        found 0 vulnerabilities
         in 1 scanned package"

      Test-HasNpmVulnerabilities -Audit $auditResult | Should -Be $false
   }

   It 'Returns $true if has vulnerabilities without vulnerabilities level paramters' {
      $auditResult = "
        found 9 vulnerabilities (2 low, 6 high, 1 critical) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult | Should -Be $true
   }

   It 'Returns $true if has more then 2 low vulnerabilities when 2 is requested' {
      $auditResult = "
        found 9 vulnerabilities (3 low) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Low 2 | Should -Be $true
   }

   It 'Returns $true if has more then 20 low vulnerabilities when 20 is requested' {
      $auditResult = "
        found 9 vulnerabilities (33 low) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Low 20 | Should -Be $true
   }

   It 'Returns $false if has 2 low vulnerabilities when 2 is requested' {
      $auditResult = "
        found 9 vulnerabilities (2 low) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Low 2 | Should -Be $false
   }

   It 'Returns $false if has 2 low vulnerabilities when 3 is requested' {
      $auditResult = "
        found 9 vulnerabilities (2 low) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Low 3 | Should -Be $false
   }

   It 'Returns $true if has more then 2 moderate vulnerabilities when 2 is requested' {
      $auditResult = "
        found 9 vulnerabilities (3 moderate) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Moderate 2 | Should -Be $true
   }

   It 'Returns $true if has more then 20 moderate vulnerabilities when 20 is requested' {
      $auditResult = "
        found 9 vulnerabilities (33 moderate) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Moderate 20 | Should -Be $true
   }

   It 'Returns $false if has 2 moderate vulnerabilities when 2 is requested' {
      $auditResult = "
        found 9 vulnerabilities (2 moderate) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Moderate 2 | Should -Be $false
   }

   It 'Returns $false if has 2 moderate vulnerabilities when 3 is requested' {
      $auditResult = "
        found 9 vulnerabilities (2 moderate) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Moderate 3 | Should -Be $false
   }

   It 'Returns $true if has more then 2 high vulnerabilities when 2 is requested' {
      $auditResult = "
        found 9 vulnerabilities (3 high) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -High 2 | Should -Be $true
   }

   It 'Returns $true if has more then 20 high vulnerabilities when 20 is requested' {
      $auditResult = "
        found 9 vulnerabilities (33 high) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -High 20 | Should -Be $true
   }

   It 'Returns $false if has 2 high vulnerabilities when 2 is requested' {
      $auditResult = "
        found 9 vulnerabilities (2 high) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -High 2 | Should -Be $false
   }

   It 'Returns $false if has 2 high vulnerabilities when 3 is requested' {
      $auditResult = "
        found 9 vulnerabilities (2 high) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -High 3 | Should -Be $false
   }

   It 'Returns $true if has more then 2 critical vulnerabilities when 2 is requested' {
      $auditResult = "
        found 9 vulnerabilities (3 critical) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Critical 2 | Should -Be $true
   }

   It 'Returns $true if has more then 20 critical vulnerabilities when 20 is requested' {
      $auditResult = "
        found 9 vulnerabilities (33 critical) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Critical 20 | Should -Be $true
   }

   It 'Returns $false if has 2 critical vulnerabilities when 2 is requested' {
      $auditResult = "
        found 9 vulnerabilities (2 critical) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Critical 2 | Should -Be $false
   }

   It 'Returns $false if has 2 critical vulnerabilities when 3 is requested' {
      $auditResult = "
        found 9 vulnerabilities (2 critical) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Critical 3 | Should -Be $false
   }

   It 'Returns $true if has 2 low 6 high and 1 critical vulnerabilities when 0 critical is requested' {
      $auditResult = "
         found 9 vulnerabilities (2 low, 6 high, 1 critical) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Low 2 -High 6 -Critical 0 | Should -Be $true
   }

   It 'Returns $false if has 2 low 6 high vulnerabilities when 1 critical is requested' {
      $auditResult = "
         found 9 vulnerabilities (2 low, 6 high) in 255 scanned packages
          run `npm audit fix` to fix 1 of them.
          8 vulnerabilities require semver-major dependency updates.
        "

      Test-HasNpmVulnerabilities -Audit $auditResult -Critical 1 | Should -Be $false
   }
}