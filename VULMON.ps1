# Security Update Checker using Official APIs
# Version 3.3 - Optional CIRCL Enrichment & UI Fixes
# This script directly queries authoritative data sources instead of web scraping

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Web
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
# ===== CONFIGURATION =====
$script:AppVersion = "3.3"
$appDataPath = Join-Path -Path $env:APPDATA -ChildPath "VULMON"
if (-not (Test-Path $appDataPath)) {
    New-Item -Path $appDataPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
}

$stateFilePath = Join-Path -Path $appDataPath -ChildPath "previous_scan_results.json"
$acknowledgedFilePath = Join-Path -Path $appDataPath -ChildPath "acknowledged_items.json"
$defaultProductListPath = Join-Path -Path $appDataPath -ChildPath "default_products.txt"

# ===== DATA SOURCE CONFIGURATIONS =====
$script:DataSources = @{
    NIST_NVD = @{
        BaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        DisplayName = "NIST NVD"
        FullName = "NIST National Vulnerability Database"
        Description = "Official US Government CVE Database"
        Website = "https://nvd.nist.gov/"
        Status = "Not Queried"
        Color = [System.Drawing.Color]::Gray
        RequiresAuth = $false
        RateLimit = @{
            WithoutKey = 5    # requests per 30 seconds
            WithKey = 50      # requests per 30 seconds
        }
    }
    MSRC = @{
        BaseURL = "https://api.msrc.microsoft.com/cvrf/v2.0"
        DisplayName = "MS MSRC"
        FullName = "Microsoft Security Response Center"
        Description = "Official Microsoft Security Updates"
        Website = "https://msrc.microsoft.com/"
        Status = "Not Queried"
        Color = [System.Drawing.Color]::Gray
        RequiresAuth = $false
        Documentation = "https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API"
    }
    CVE_CIRCL = @{
        BaseURL = "https://cve.circl.lu/api/cve"
        DisplayName = "CIRCL"
        FullName = "CIRCL CVE Search"
        Description = "Fast CVE Lookup & Supplementary Data"
        Website = "https://cve.circl.lu/"
        Status = "Not Queried"
        Color = [System.Drawing.Color]::Gray
        RequiresAuth = $false
    }
}

# ===== API HELPER FUNCTIONS =====

function Update-SourceStatus {
    param(
        [string]$SourceKey,
        [string]$Status,
        [System.Drawing.Color]$Color
    )
    $script:DataSources[$SourceKey].Status = $Status
    $script:DataSources[$SourceKey].Color = $Color
    
    # Update the UI label if it exists
    if ($script:sourceLabels -and $script:sourceLabels.ContainsKey($SourceKey)) {
        $label = $script:sourceLabels[$SourceKey]
        $label.Text = "$($script:DataSources[$SourceKey].DisplayName): $Status"
        $label.ForeColor = $Color
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Get-NVDApiKey {
    $keyPath = Join-Path -Path $appDataPath -ChildPath "nvd_api_key.txt"
    if (Test-Path $keyPath) {
        return Get-Content $keyPath -Raw
    }
    return $null
}

function Set-NVDApiKey {
    param([string]$ApiKey)
    $keyPath = Join-Path -Path $appDataPath -ChildPath "nvd_api_key.txt"
    $ApiKey | Set-Content -Path $keyPath -NoNewline
}

function Invoke-NVDSearch {
    param(
        [string]$KeywordSearch,
        [DateTime]$StartDate,
        [DateTime]$EndDate,
        [int]$ResultsPerPage = 20,
        [string[]]$Severities = @(),
		[bool]$HasKev = $false
    )
    
    Update-SourceStatus -SourceKey "NIST_NVD" -Status "Querying..." -Color ([System.Drawing.Color]::Blue)
    
    try {
        $headers = @{
            'Accept' = 'application/json'
        }
        
        $apiKey = Get-NVDApiKey
        if ($apiKey) {
            $headers['apiKey'] = $apiKey
        }
        
        $params = @{
            'keywordSearch' = $KeywordSearch
            'pubStartDate' = $StartDate.ToString('yyyy-MM-ddTHH:mm:ss.000')
            'pubEndDate' = $EndDate.ToString('yyyy-MM-ddTHH:mm:ss.000')
            'resultsPerPage' = $ResultsPerPage
        }
        
        # Build the main query string from the $params hashtable
        $queryString = ($params.GetEnumerator() | ForEach-Object { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join '&'
        
        # Build the severity query string, but only if KEV filter is NOT active
        if ($Severities.Count -gt 0 -and (-not $HasKev)) {
            $severityQueryString = ($Severities | ForEach-Object { "cvssV3Severity=$([System.Web.HttpUtility]::UrlEncode($_))" }) -join '&'
            $queryString = "$queryString&$severityQueryString"
        }

        # Add the KEV filter if selected
        if ($HasKev) {
            $queryString = "$queryString&hasKev"
        }

        $uri = "$($script:DataSources.NIST_NVD.BaseURL)?$queryString"
		# Add the KEV filter if selected

		if ($HasKev) {

		$queryString = "$queryString&hasKev"

		}
        $uri = "$($script:DataSources.NIST_NVD.BaseURL)?$queryString"
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 30 -ErrorAction Stop
        
        Update-SourceStatus -SourceKey "NIST_NVD" -Status "✓ Active" -Color ([System.Drawing.Color]::Green)
        
        Start-Sleep -Milliseconds 600
        
        return $response
    } catch {
        Update-SourceStatus -SourceKey "NIST_NVD" -Status "✗ Error" -Color ([System.Drawing.Color]::Red)
        Write-Warning "NVD API Error: $($_.Exception.Message)"
        return $null
    }
}

function Get-CVEDetails {
    param([string]$CveId)
    
    Update-SourceStatus -SourceKey "CVE_CIRCL" -Status "Querying..." -Color ([System.Drawing.Color]::Blue)
    
    try {
        $uri = "$($script:DataSources.CVE_CIRCL.BaseURL)/$CveId"
        $response = Invoke-RestMethod -Uri $uri -TimeoutSec 15 -ErrorAction Stop
        
        Update-SourceStatus -SourceKey "CVE_CIRCL" -Status "✓ Active" -Color ([System.Drawing.Color]::Green)
        
        $severity = "UNKNOWN"
        $score = 0
        
        if ($response.cvss) {
            $score = [double]$response.cvss
        }
        
        if ($score -ge 9.0) { $severity = "CRITICAL" }
        elseif ($score -ge 7.0) { $severity = "HIGH" }
        elseif ($score -ge 4.0) { $severity = "MEDIUM" }
        elseif ($score -gt 0) { $severity = "LOW" }
        
        return @{
            Score = $score
            Severity = $severity
            Summary = $response.summary
            Published = $response.Published
            Modified = $response.Modified
        }
    } catch {
        Update-SourceStatus -SourceKey "CVE_CIRCL" -Status "⚠ Limited" -Color ([System.Drawing.Color]::Orange)
        Write-Warning "Could not fetch details for $CveId : $($_.Exception.Message)"
        return @{
            Score = 0
            Severity = "UNKNOWN"
            Summary = ""
            Published = ""
            Modified = ""
        }
    }
}

function Search-VulnerabilitiesByProduct {
    param(
        [string[]]$ProductNames,
        [DateTime]$StartDate,
        [DateTime]$EndDate,
        [bool]$EnrichData = $false,
        [string[]]$Severities = @(),
		[bool]$HasKev = $false
    )
    
    $results = @()
    
    foreach ($product in $ProductNames) {
        if ([string]::IsNullOrWhiteSpace($product)) { continue }
        
        Write-Host "Searching vulnerabilities for: $product"
        
        $nvdResults = Invoke-NVDSearch -KeywordSearch $product -StartDate $StartDate -EndDate $EndDate -Severities $Severities -HasKev $HasKev
        
        if ($nvdResults -and $nvdResults.vulnerabilities) {
            foreach ($vuln in $nvdResults.vulnerabilities) {
                $cve = $vuln.cve
                
                $cveId = $cve.id
                $description = ""
                if ($cve.descriptions) {
                    $description = ($cve.descriptions | Where-Object { $_.lang -eq 'en' })[0].value
                }
                
                $published = $cve.published
                $modified = $cve.lastModified
                
                $score = 0
                $severity = "UNKNOWN"
                $vector = ""
                
                if ($cve.metrics) {
                    if ($cve.metrics.cvssMetricV31) {
                        $cvss = $cve.metrics.cvssMetricV31[0].cvssData
                        $score = $cvss.baseScore
                        $severity = $cvss.baseSeverity
                        $vector = $cvss.vectorString
                    }
                    elseif ($cve.metrics.cvssMetricV30) {
                        $cvss = $cve.metrics.cvssMetricV30[0].cvssData
                        $score = $cvss.baseScore
                        $severity = $cvss.baseSeverity
                        $vector = $cvss.vectorString
                    }
                    elseif ($cve.metrics.cvssMetricV2) {
                        $cvss = $cve.metrics.cvssMetricV2[0].cvssData
                        $score = $cvss.baseScore
                        if ($score -ge 7.0) { $severity = "HIGH" }
                        elseif ($score -ge 4.0) { $severity = "MEDIUM" }
                        else { $severity = "LOW" }
                        $vector = $cvss.vectorString
                    }
                }
                
                if ($EnrichData) {
                    $labelStatus.Text = "Enriching $cveId with CIRCL data (this may take a moment)..."
                    [System.Windows.Forms.Application]::DoEvents()
                    
                    $enrichedDetails = Get-CVEDetails -CveId $cveId
                    
                    # Overwrite NVD data if CIRCL provides a score
                    if ($enrichedDetails.Score -gt 0) {
                        $score = $enrichedDetails.Score
                        $severity = $enrichedDetails.Severity
                    }
                    
                    # Supplement description if NVD's is blank
                    if ([string]::IsNullOrWhiteSpace($description) -and -not [string]::IsNullOrWhiteSpace($enrichedDetails.Summary)) {
                        $description = "CIRCL: " + $enrichedDetails.Summary
                    }
                }
                
                $results += [PSCustomObject]@{
                    Product = $product
                    CVE = $cveId
                    Severity = $severity.ToUpper()
                    Score = $score
                    Description = $description
                    Published = $published
                    Modified = $modified
                    Vector = $vector
                    Source = "NIST NVD"
                }
            }
        }
    }
    
    return $results
}

function Search-MSRCUpdates {
    param(
        [string[]]$ProductNames,
        [DateTime]$StartDate,
        [string[]]$Severities = @(),
		[bool]$HasKev = $false
    )
if ($HasKev) {
        Update-SourceStatus -SourceKey "MSRC" -Status "Skipped (KEV)" -Color ([System.Drawing.Color]::DarkGray)
        return @()
    }
    if (-not (Get-Module -ListAvailable -Name MsrcSecurityUpdates)) {
        Update-SourceStatus -SourceKey "MSRC" -Status "Not Available" -Color ([System.Drawing.Color]::DarkGray)
        return @()
    }

    Update-SourceStatus -SourceKey "MSRC" -Status "Querying..." -Color ([System.Drawing.Color]::Blue)
    
    try {
        # We must explicitly import the module from our local app data path
# to avoid PowerShell loading an old/cached version from a broken path
$localModulePath = Join-Path -Path $appDataPath -ChildPath "Modules"
$moduleManifest = ""

# Find the module manifest file. It's usually in a version-named subfolder.
$moduleRoot = Join-Path -Path $localModulePath -ChildPath "MsrcSecurityUpdates"
if (Test-Path $moduleRoot) {
    $moduleVersionFolder = Get-ChildItem -Path $moduleRoot | Sort-Object Name -Descending | Select-Object -First 1
    if ($moduleVersionFolder) {
        $moduleManifest = Join-Path -Path $moduleVersionFolder.FullName -ChildPath "MsrcSecurityUpdates.psd1"
    }
}

if (-not (Test-Path $moduleManifest)) {
    Write-Warning "Could not find MSRC module manifest in $localModulePath. Query will fail."
    Update-SourceStatus -SourceKey "MSRC" -Status "✗ Not Found" -Color ([System.Drawing.Color]::Red)
    return @()
}
        
# Import the module directly from its manifest file
Import-Module -Name $moduleManifest -Force
        Import-Module -Name "MsrcSecurityUpdates" -Force
        
        
        # Get all MSRC updates since the start date
        # Get ALL updates (bypassing the failing parameter) and filter in-memory.
$allUpdates = Get-MsrcSecurityUpdate -ErrorAction Stop
$filteredUpdates = $allUpdates | Where-Object { $_.InitialReleaseDate -ge $StartDate }

# Only filter by severity if severities were actually selected
if ($Severities.Count -gt 0) {
    $filteredUpdates = $filteredUpdates | Where-Object { $Severities -contains $_.Severity.ToUpper() }
}
        
        $results = @()
        
        foreach ($update in $filteredUpdates) {
            # MSRC $update.Product is an array of strings (e.g., "Windows 11 Version 22H2")
            # We'll join them into one string and check if the user's product name is in it
            $msrcProductString = $update.Product -join ' '

            foreach ($userProduct in $ProductNames) {
                # Use regex match for flexible "contains" logic
                if ($msrcProductString -match [regex]::Escape($userProduct)) {
                    $results += [PSCustomObject]@{
                        Product = $userProduct # Use the user's term for consistency
                        CVE = $update.CVE
                        Severity = $update.Severity.ToUpper()
                        Score = $update.BaseScore
                        Description = $update.Title
                        Published = $update.InitialReleaseDate
                        Modified = $update.CurrentReleaseDate
                        Vector = $update.VectorString
                        Source = "MS MSRC"
                    }
                    # Got a match for this update, no need to check other user products
                    break 
                }
            }
        }
        
        Update-SourceStatus -SourceKey "MSRC" -Status "✓ Active" -Color ([System.Drawing.Color]::Green)
        return $results
        
    } catch {
        Update-SourceStatus -SourceKey "MSRC" -Status "✗ Error" -Color ([System.Drawing.Color]::Red)
        Write-Warning "MSRC Module Error: $($_.Exception.Message)"
        return @()
    }
}

# ===== JSON HELPER FUNCTIONS =====

function Save-JsonSafely {
    param([object]$Data, [string]$Path)
    try {
        $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -ErrorAction Stop
        return $true
    } catch {
        Write-Warning "Failed to save JSON to $Path : $($_.Exception.Message)"
        return $false
    }
}

function Load-JsonSafely {
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            return Get-Content -Path $Path -Raw | ConvertFrom-Json
        } catch {
            Write-Warning "Failed to load JSON from $Path : $($_.Exception.Message)"
        }
    }
    return $null
}

# ===== PRODUCT LIST FUNCTIONS =====

function Save-ProductList {
    param([string]$FilePath, [string[]]$Products)
    try {
        $Products -join [Environment]::NewLine | Set-Content -Path $FilePath -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Load-ProductList {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        try {
            # Get-Content without -Raw automatically returns an array of strings, one per line.
            # This correctly handles all line-ending types (\n, \r\n, etc.)
            $content = Get-Content -Path $FilePath
            return $content | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        } catch {
            return @()
        }
    }
    return @()
}

# ===== GUI SETUP =====

$form = New-Object System.Windows.Forms.Form
$form.Text = "Vulnerability Monitor (VULMON) v$script:AppVersion"
$form.Size = New-Object System.Drawing.Size(1300, 900)
$form.StartPosition = "CenterScreen"
$form.MinimumSize = New-Object System.Drawing.Size(1300, 900)

# Top Panel - Input Controls
$panelTop = New-Object System.Windows.Forms.Panel
$panelTop.Dock = "Top"
$panelTop.Height = 380
$panelTop.BorderStyle = "FixedSingle"
$form.Controls.Add($panelTop)

# LEFT COLUMN - Products

$labelProducts = New-Object System.Windows.Forms.Label
$labelProducts.Location = New-Object System.Drawing.Point(10, 10)
$labelProducts.Size = New-Object System.Drawing.Size(280, 20)
$labelProducts.Text = "Products to Monitor (one per line):"
$labelProducts.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$panelTop.Controls.Add($labelProducts)

$textboxProducts = New-Object System.Windows.Forms.TextBox
$textboxProducts.Location = New-Object System.Drawing.Point(10, 35)
$textboxProducts.Size = New-Object System.Drawing.Size(280, 160)
$textboxProducts.Multiline = $true
$textboxProducts.ScrollBars = "Vertical"
$textboxProducts.Font = New-Object System.Drawing.Font("Consolas", 9)
$defaultProducts = Load-ProductList -FilePath $defaultProductListPath
if ($defaultProducts.Count -gt 0) {
    $textboxProducts.Text = $defaultProducts -join [Environment]::NewLine
} else {
    $textboxProducts.Text = "Chrome`nFirefox`nAdobe Reader`nJava`nPython" -replace "`n", [Environment]::NewLine
}
$panelTop.Controls.Add($textboxProducts)

# Product List Buttons
$buttonLoadList = New-Object System.Windows.Forms.Button
$buttonLoadList.Location = New-Object System.Drawing.Point(10, 200)
$buttonLoadList.Size = New-Object System.Drawing.Size(90, 25)
$buttonLoadList.Text = "Load List..."
$panelTop.Controls.Add($buttonLoadList)

$buttonSaveList = New-Object System.Windows.Forms.Button
$buttonSaveList.Location = New-Object System.Drawing.Point(105, 200)
$buttonSaveList.Size = New-Object System.Drawing.Size(90, 25)
$buttonSaveList.Text = "Save List..."
$panelTop.Controls.Add($buttonSaveList)

$buttonSetDefault = New-Object System.Windows.Forms.Button
$buttonSetDefault.Location = New-Object System.Drawing.Point(200, 200)
$buttonSetDefault.Size = New-Object System.Drawing.Size(90, 25)
$buttonSetDefault.Text = "Set Default"
$panelTop.Controls.Add($buttonSetDefault)

# MIDDLE COLUMN - Settings

$labelStartDate = New-Object System.Windows.Forms.Label
$labelStartDate.Location = New-Object System.Drawing.Point(310, 10)
$labelStartDate.Size = New-Object System.Drawing.Size(120, 20)
$labelStartDate.Text = "Start Date:"
$labelStartDate.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$panelTop.Controls.Add($labelStartDate)

$datePickerStart = New-Object System.Windows.Forms.DateTimePicker
$datePickerStart.Location = New-Object System.Drawing.Point(310, 35)
$datePickerStart.Size = New-Object System.Drawing.Size(120, 20)
$datePickerStart.Format = "Short"
$datePickerStart.Value = (Get-Date).AddDays(-30)
$panelTop.Controls.Add($datePickerStart)

$labelEndDate = New-Object System.Windows.Forms.Label
$labelEndDate.Location = New-Object System.Drawing.Point(450, 10)
$labelEndDate.Size = New-Object System.Drawing.Size(120, 20)
$labelEndDate.Text = "End Date:"
$labelEndDate.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$panelTop.Controls.Add($labelEndDate)

$datePickerEnd = New-Object System.Windows.Forms.DateTimePicker
$datePickerEnd.Location = New-Object System.Drawing.Point(450, 35)
$datePickerEnd.Size = New-Object System.Drawing.Size(120, 20)
$datePickerEnd.Format = "Short"
$datePickerEnd.Value = (Get-Date)
$panelTop.Controls.Add($datePickerEnd)

$checkboxEnrichData = New-Object System.Windows.Forms.CheckBox
$checkboxEnrichData.Location = New-Object System.Drawing.Point(310, 65)
$checkboxEnrichData.Size = New-Object System.Drawing.Size(400, 25)
$checkboxEnrichData.Text = "Enrich CVEs with CIRCL (Slower, but more detail)"
$checkboxEnrichData.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$panelTop.Controls.Add($checkboxEnrichData)

$checkboxCritical = New-Object System.Windows.Forms.CheckBox
$checkboxCritical.Location = New-Object System.Drawing.Point(325, 90)
$checkboxCritical.Size = New-Object System.Drawing.Size(100, 25)
$checkboxCritical.Text = "Critical"
$checkboxCritical.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$checkboxCritical.Checked = $true
$panelTop.Controls.Add($checkboxCritical)

$checkboxHigh = New-Object System.Windows.Forms.CheckBox
$checkboxHigh.Location = New-Object System.Drawing.Point(435, 90)
$checkboxHigh.Size = New-Object System.Drawing.Size(100, 25)
$checkboxHigh.Text = "High"
$checkboxHigh.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$checkboxHigh.Checked = $true
$checkboxCISA = New-Object System.Windows.Forms.CheckBox
$checkboxCISA.Location = New-Object System.Drawing.Point(310, 120)
$checkboxCISA.Size = New-Object System.Drawing.Size(300, 25)
$checkboxCISA.Text = "Show CISA Known Exploited (KEV) Only"
$checkboxCISA.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$panelTop.Controls.Add($checkboxCISA)
$panelTop.Controls.Add($checkboxHigh)

# API Key Configuration
$labelApiKey = New-Object System.Windows.Forms.Label
$labelApiKey.Location = New-Object System.Drawing.Point(310, 155)
$labelApiKey.Size = New-Object System.Drawing.Size(350, 20)
$labelApiKey.Text = "NVD API Key (optional - increases rate limit 10x):"
$labelApiKey.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$panelTop.Controls.Add($labelApiKey)

$textboxApiKey = New-Object System.Windows.Forms.TextBox
$textboxApiKey.Location = New-Object System.Drawing.Point(310, 180)
$textboxApiKey.Size = New-Object System.Drawing.Size(350, 20)
$textboxApiKey.UseSystemPasswordChar = $true
$existingKey = Get-NVDApiKey
if ($existingKey) { $textboxApiKey.Text = $existingKey }
$panelTop.Controls.Add($textboxApiKey)

$buttonSaveApiKey = New-Object System.Windows.Forms.Button
$buttonSaveApiKey.Location = New-Object System.Drawing.Point(670, 178)
$buttonSaveApiKey.Size = New-Object System.Drawing.Size(80, 25)
$buttonSaveApiKey.Text = "Save Key"
$panelTop.Controls.Add($buttonSaveApiKey)

$linkLabelGetApiKey = New-Object System.Windows.Forms.LinkLabel
$linkLabelGetApiKey.Location = New-Object System.Drawing.Point(310, 205)
$linkLabelGetApiKey.Size = New-Object System.Drawing.Size(400, 20)
$linkLabelGetApiKey.Text = "Get a free NVD API key (5-min signup, increases rate limit to 50/30s)"
$linkLabelGetApiKey.LinkColor = [System.Drawing.Color]::Blue
$panelTop.Controls.Add($linkLabelGetApiKey)

# Data Sources Panel - NEW!
$groupBoxSources = New-Object System.Windows.Forms.GroupBox
$groupBoxSources.Location = New-Object System.Drawing.Point(310, 235)
$groupBoxSources.Size = New-Object System.Drawing.Size(440, 140)
$groupBoxSources.Text = "Data Sources (Official APIs - No Web Scraping)"
$groupBoxSources.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$panelTop.Controls.Add($groupBoxSources)

# Initialize source labels dictionary
$script:sourceLabels = @{}

# NIST NVD Source
$labelNVD = New-Object System.Windows.Forms.Label
$labelNVD.Location = New-Object System.Drawing.Point(10, 20)
$labelNVD.Size = New-Object System.Drawing.Size(150, 20)
$labelNVD.Text = "NIST NVD: Not Queried"
$labelNVD.ForeColor = [System.Drawing.Color]::Gray
$labelNVD.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$groupBoxSources.Controls.Add($labelNVD)
$script:sourceLabels["NIST_NVD"] = $labelNVD

$labelNVDDesc = New-Object System.Windows.Forms.Label
$labelNVDDesc.Location = New-Object System.Drawing.Point(20, 38)
$labelNVDDesc.Size = New-Object System.Drawing.Size(410, 15)
$labelNVDDesc.Text = "Official US Government CVE Database - Primary vulnerability data source"
$labelNVDDesc.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$labelNVDDesc.ForeColor = [System.Drawing.Color]::DarkGray
$groupBoxSources.Controls.Add($labelNVDDesc)

# CIRCL Source
$labelCIRCL = New-Object System.Windows.Forms.Label
$labelCIRCL.Location = New-Object System.Drawing.Point(10, 55)
$labelCIRCL.Size = New-Object System.Drawing.Size(150, 20)
$labelCIRCL.Text = "CIRCL: Not Queried"
$labelCIRCL.ForeColor = [System.Drawing.Color]::Gray
$labelCIRCL.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$groupBoxSources.Controls.Add($labelCIRCL)
$script:sourceLabels["CVE_CIRCL"] = $labelCIRCL

$labelCIRCLDesc = New-Object System.Windows.Forms.Label
$labelCIRCLDesc.Location = New-Object System.Drawing.Point(20, 73)
$labelCIRCLDesc.Size = New-Object System.Drawing.Size(410, 15)
$labelCIRCLDesc.Text = "Fast CVE lookup & supplementary data - Enriches vulnerability details"
$labelCIRCLDesc.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$labelCIRCLDesc.ForeColor = [System.Drawing.Color]::DarkGray
$groupBoxSources.Controls.Add($labelCIRCLDesc)

# MSRC Source
$labelMSRC = New-Object System.Windows.Forms.Label
$labelMSRC.Location = New-Object System.Drawing.Point(10, 90)
$labelMSRC.Size = New-Object System.Drawing.Size(180, 20)
$labelMSRC.Text = "MS MSRC: Not Queried"
$labelMSRC.ForeColor = [System.Drawing.Color]::Gray
$labelMSRC.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$groupBoxSources.Controls.Add($labelMSRC)
$script:sourceLabels["MSRC"] = $labelMSRC

$labelMSRCDesc = New-Object System.Windows.Forms.Label
$labelMSRCDesc.Location = New-Object System.Drawing.Point(20, 108)
$labelMSRCDesc.Size = New-Object System.Drawing.Size(410, 15)
$labelMSRCDesc.Text = "Microsoft Security Response Center - Official MS security updates (requires module)"
$labelMSRCDesc.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$labelMSRCDesc.ForeColor = [System.Drawing.Color]::DarkGray
$groupBoxSources.Controls.Add($labelMSRCDesc)

# RIGHT COLUMN - Action Buttons

$buttonCheck = New-Object System.Windows.Forms.Button
$buttonCheck.Location = New-Object System.Drawing.Point(780, 35)
$buttonCheck.Size = New-Object System.Drawing.Size(140, 40)
$buttonCheck.Text = "Check Updates"
$buttonCheck.BackColor = [System.Drawing.Color]::LightGreen
$buttonCheck.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$panelTop.Controls.Add($buttonCheck)

$buttonClear = New-Object System.Windows.Forms.Button
$buttonClear.Location = New-Object System.Drawing.Point(930, 35)
$buttonClear.Size = New-Object System.Drawing.Size(120, 40)
$buttonClear.Text = "Clear Results"
$panelTop.Controls.Add($buttonClear)

$buttonExport = New-Object System.Windows.Forms.Button
$buttonExport.Location = New-Object System.Drawing.Point(1060, 35)
$buttonExport.Size = New-Object System.Drawing.Size(120, 40)
$buttonExport.Text = "Export to CSV"
$buttonExport.Enabled = $false
$panelTop.Controls.Add($buttonExport)

$buttonHelp = New-Object System.Windows.Forms.Button
$buttonHelp.Location = New-Object System.Drawing.Point(1190, 35)
$buttonHelp.Size = New-Object System.Drawing.Size(80, 40)
$buttonHelp.Text = "Help"
$panelTop.Controls.Add($buttonHelp)

# Additional buttons below
$buttonInstallMSRC = New-Object System.Windows.Forms.Button
$buttonInstallMSRC.Location = New-Object System.Drawing.Point(780, 85)
$buttonInstallMSRC.Size = New-Object System.Drawing.Size(200, 30)
$buttonInstallMSRC.Text = "Install MSRC Module"
$buttonInstallMSRC.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$panelTop.Controls.Add($buttonInstallMSRC)

$labelMSRCInfo = New-Object System.Windows.Forms.Label
$labelMSRCInfo.Location = New-Object System.Drawing.Point(780, 120)
$labelMSRCInfo.Size = New-Object System.Drawing.Size(490, 40)
$labelMSRCInfo.Text = "Optional: Install Microsoft Security Response Center module for enhanced Microsoft product monitoring. Only needed if you monitor Windows, Office, Edge, etc."
$labelMSRCInfo.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$panelTop.Controls.Add($labelMSRCInfo)

# Legend
$labelLegend = New-Object System.Windows.Forms.Label
$labelLegend.Location = New-Object System.Drawing.Point(780, 170)
$labelLegend.Size = New-Object System.Drawing.Size(490, 60)
$labelLegend.Text = @"
Status Indicators:  ✓ Active (queried successfully)  |  ⚠ Limited (partial data)
✗ Error (query failed)  |  Not Queried (not yet used in this session)

Source Column: Shows which API provided each vulnerability record
"@
$labelLegend.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$labelLegend.ForeColor = [System.Drawing.Color]::DarkSlateGray
$panelTop.Controls.Add($labelLegend)

# Status Labels
$labelStatus = New-Object System.Windows.Forms.Label
$labelStatus.Location = New-Object System.Drawing.Point(10, 325)
$labelStatus.Size = New-Object System.Drawing.Size(1260, 50)
$labelStatus.Text = "Ready. Using official APIs: NIST NVD (primary), CIRCL CVE (enrichment), Microsoft MSRC (optional)"
$labelStatus.ForeColor = [System.Drawing.Color]::Blue
$labelStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$panelTop.Controls.Add($labelStatus)

# DataGridView
$dataGridResults = New-Object System.Windows.Forms.DataGridView
$dataGridResults.Location = New-Object System.Drawing.Point(10, 390)
$dataGridResults.Size = New-Object System.Drawing.Size(1260, 450)
$dataGridResults.AllowUserToAddRows = $false
$dataGridResults.AllowUserToDeleteRows = $false
$dataGridResults.ReadOnly = $true
$dataGridResults.SelectionMode = "FullRowSelect"
$dataGridResults.MultiSelect = $true
$dataGridResults.AutoSizeColumnsMode = "Fill"
$form.Controls.Add($dataGridResults)

# Configure columns
$columns = @(
    @{Name="Product"; Width=120},
    @{Name="CVE"; Width=110},
    @{Name="Severity"; Width=90},
    @{Name="Score"; Width=60},
    @{Name="Description"; Width=500},
    @{Name="Published"; Width=100},
    @{Name="Source"; Width=90},
    @{Name="Status"; Width=90}
)

foreach ($col in $columns) {
    $column = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $column.Name = $col.Name
    $column.HeaderText = $col.Name
    $column.Width = $col.Width
    $dataGridResults.Columns.Add($column) | Out-Null
}

# Bottom Panel
$panelBottom = New-Object System.Windows.Forms.Panel
$panelBottom.Dock = "Bottom"
$panelBottom.Height = 50
$form.Controls.Add($panelBottom)

$labelStats = New-Object System.Windows.Forms.Label
$labelStats.Location = New-Object System.Drawing.Point(10, 10)
$labelStats.Size = New-Object System.Drawing.Size(1250, 30)
$labelStats.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$panelBottom.Controls.Add($labelStats)

# ===== EVENT HANDLERS =====

$checkboxCISA.Add_Click({
    if ($checkboxCISA.Checked) {
        $checkboxCritical.Enabled = $false
        $checkboxHigh.Enabled = $false
    } else {
        $checkboxCritical.Enabled = $true
        $checkboxHigh.Enabled = $true
    }
})

$buttonLoadList.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
    $openFileDialog.Title = "Load Product List"
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")
    
    if ($openFileDialog.ShowDialog() -eq "OK") {
        try {
            $products = Load-ProductList -FilePath $openFileDialog.FileName
            if ($products.Count -gt 0) {
                $textboxProducts.Text = $products -join [Environment]::NewLine
                $labelStatus.Text = "Loaded $($products.Count) products from $($openFileDialog.FileName)"
                $labelStatus.ForeColor = [System.Drawing.Color]::Green
            } else {
                [System.Windows.Forms.MessageBox]::Show("No products found in file.", "Empty File", "OK", "Warning")
            }
        } catch {
            $labelStatus.Text = "Error loading file: $($_.Exception.Message)"
            $labelStatus.ForeColor = [System.Drawing.Color]::Red
        }
    }
})


$buttonSaveList.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
    $saveFileDialog.Title = "Save Product List"
    $saveFileDialog.FileName = "ProductList.txt"
    $saveFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")
    
    if ($saveFileDialog.ShowDialog() -eq "OK") {
        try {
            $products = $textboxProducts.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            if (Save-ProductList -FilePath $saveFileDialog.FileName -Products $products) {
                $labelStatus.Text = "Saved $($products.Count) products to $($saveFileDialog.FileName)"
                $labelStatus.ForeColor = [System.Drawing.Color]::Green
            } else {
                $labelStatus.Text = "Error saving product list"
                $labelStatus.ForeColor = [System.Drawing.Color]::Red
            }
        } catch {
            $labelStatus.Text = "Error: $($_.Exception.Message)"
            $labelStatus.ForeColor = [System.Drawing.Color]::Red
        }
    }
})

$buttonSetDefault.Add_Click({
    try {
        $products = $textboxProducts.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        if (Save-ProductList -FilePath $defaultProductListPath -Products $products) {
            $labelStatus.Text = "Saved as default product list. Will load automatically next time."
            $labelStatus.ForeColor = [System.Drawing.Color]::Green
        } else {
            $labelStatus.Text = "Error saving default list"
            $labelStatus.ForeColor = [System.Drawing.Color]::Red
        }
    } catch {
        $labelStatus.Text = "Error: $($_.Exception.Message)"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
    }
})

$buttonSaveApiKey.Add_Click({
    $key = $textboxApiKey.Text.Trim()
    if ($key) {
        Set-NVDApiKey -ApiKey $key
        $labelStatus.Text = "API key saved. Rate limit increased to 50 requests/30 seconds"
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
    }
})

$linkLabelGetApiKey.Add_LinkClicked({
    Start-Process "https://nvd.nist.gov/developers/request-an-api-key"
})

$buttonInstallMSRC.Add_Click({
    $labelStatus.Text = "Installing MsrcSecurityUpdates module... This may take a minute..."
    $labelStatus.ForeColor = [System.Drawing.Color]::Blue
    [System.Windows.Forms.Application]::DoEvents()
    
    # Define a stable, local path for our modules
    $localModulePath = Join-Path -Path $appDataPath -ChildPath "Modules"
    if (-not (Test-Path $localModulePath)) {
        New-Item -Path $localModulePath -ItemType Directory -ErrorAction Stop | Out-Null
    }
    
    # Prepend our local path to the module search paths for this session
    $env:PSModulePath = "$localModulePath;$($env:PSModulePath)"

    try {
        if (Get-Module -ListAvailable -Name MsrcSecurityUpdates) {
            [System.Windows.Forms.MessageBox]::Show("MsrcSecurityUpdates module is already installed!", "Already Installed", "OK", "Information")
            $labelStatus.Text = "MSRC module already installed"
            $labelStatus.ForeColor = [System.Drawing.Color]::Green
            Update-SourceStatus -SourceKey "MSRC" -Status "✓ Available" -Color ([System.Drawing.Color]::Green)
        } else {
            $labelStatus.Text = "Installing MsrcSecurityUpdates to local app data..."
            [System.Windows.Forms.Application]::DoEvents()

            # 1. Use Install-Module with -TrustRepository to skip the hidden prompt.
            # 2. -Scope CurrentUser will install to our $localModulePath because it's first in $env:PSModulePath
            Install-Module -Name MsrcSecurityUpdates -Scope CurrentUser -Force -TrustRepository -ErrorAction Stop
            
            # 3. Unblock the downloaded files to satisfy Execution Policy (Mark of the Web)
            Get-ChildItem -Path $localModulePath -Recurse | Unblock-File
            
            # Now, import it directly from that path
            Import-Module -Name "MsrcSecurityUpdates" -Force
            
            [System.Windows.Forms.MessageBox]::Show("MsrcSecurityUpdates module installed successfully!", "Success", "OK", "Information")
            $labelStatus.Text = "MSRC module installed successfully"
            $labelStatus.ForeColor = [System.Drawing.Color]::Green
            Update-SourceStatus -SourceKey "MSRC" -Status "✓ Available" -Color ([System.Drawing.Color]::Green)
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error installing module: $($_.Exception.Message)`n`nYou can install manually: Install-Module -Name MsrcSecurityUpdates", "Installation Error", "OK", "Error")
        $labelStatus.Text = "Error installing MSRC module"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
        Update-SourceStatus -SourceKey "MSRC" -Status "✗ Not Available" -Color ([System.Drawing.Color]::Red)
    }
})

$buttonCheck.Add_Click({
    # Reset all source statuses
    foreach ($sourceKey in $script:DataSources.Keys) {
        Update-SourceStatus -SourceKey $sourceKey -Status "Not Queried" -Color ([System.Drawing.Color]::Gray)
    }
    
    $labelStatus.Text = "Searching vulnerabilities using official APIs..."
    $labelStatus.ForeColor = [System.Drawing.Color]::Blue
    $dataGridResults.Rows.Clear()
    $buttonExport.Enabled = $false
    
    [System.Windows.Forms.Application]::DoEvents()
    
    try {
        $products = $textboxProducts.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        
        if ($products.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("Please enter at least one product name.", "No Products", "OK", "Warning")
            $labelStatus.Text = "Ready"
            $labelStatus.ForeColor = [System.Drawing.Color]::Blue
            return
        }
        
        # Read current checkbox states for severity filtering
        $selectedSeverities = @()
        if ($checkboxCritical.Checked) { $selectedSeverities += "CRITICAL" }
        if ($checkboxHigh.Checked) { $selectedSeverities += "HIGH" }
        
        # Get date range
        $startDate = $datePickerStart.Value.Date
        $endDate = $datePickerEnd.Value.Date.AddDays(1).AddTicks(-1)
        
        if ($startDate -gt $endDate) {
            [System.Windows.Forms.MessageBox]::Show("The Start Date cannot be after the End Date.", "Invalid Date Range", "OK", "Warning")
            return
        }
        
        $hasKevFilter = $checkboxCISA.Checked
$nvdResults = Search-VulnerabilitiesByProduct -ProductNames $products -StartDate $startDate -EndDate $endDate -EnrichData $checkboxEnrichData.Checked -Severities $selectedSeverities -HasKev $hasKevFilter
$msrcResults = Search-MSRCUpdates -ProductNames $products -StartDate $startDate -Severities $selectedSeverities -HasKev $hasKevFilter
        
$results = $nvdResults + $msrcResults
        
        if ($results.Count -eq 0) {
            $labelStatus.Text = "No vulnerabilities found for the specified products in the date range"
            $labelStatus.ForeColor = [System.Drawing.Color]::Orange
            return
        }
        
        $previousResults = Load-JsonSafely -Path $stateFilePath
        $previousCVEs = @{}
        if ($previousResults) {
            foreach ($prev in $previousResults) {
                $previousCVEs[$prev.CVE] = $true
            }
        }
        
        $criticalCount = 0
        $highCount = 0
        $newCount = 0
        
        foreach ($result in $results | Sort-Object Score -Descending) {
            $status = "Existing"
            $rowColor = [System.Drawing.Color]::White
            
            if (-not $previousCVEs.ContainsKey($result.CVE)) {
                $status = "NEW"
                $newCount++
                $rowColor = [System.Drawing.Color]::LightCoral
            }
            
            if ($result.Severity -eq "CRITICAL") {
                $criticalCount++
                if ($status -ne "NEW") {
                    $rowColor = [System.Drawing.Color]::MistyRose
                }
            } elseif ($result.Severity -eq "HIGH") {
                $highCount++
                if ($status -ne "NEW") {
                    $rowColor = [System.Drawing.Color]::LightYellow
                }
            }
            
            $rowIndex = $dataGridResults.Rows.Add(
                $result.Product,
                $result.CVE,
                $result.Severity,
                $result.Score,
                $result.Description,
                ([DateTime]::Parse($result.Published).ToString('yyyy-MM-dd')),
                $result.Source,
                $status
            )
            $dataGridResults.Rows[$rowIndex].DefaultCellStyle.BackColor = $rowColor
        }
        
        Save-JsonSafely -Data $results -Path $stateFilePath | Out-Null
        
        $labelStats.Text = "Found: $($results.Count) vulnerabilities | $criticalCount Critical | $highCount High"
        if ($newCount -gt 0) {
            $labelStats.Text += " | $newCount NEW"
        }
        
        $labelStatus.Text = "Successfully retrieved $($results.Count) vulnerabilities from official APIs. Check source status indicators above."
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
        $buttonExport.Enabled = $true
        
    } catch {
        $labelStatus.Text = "Error: $($_.Exception.Message)"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
    }
})

$buttonClear.Add_Click({
    $dataGridResults.Rows.Clear()
    $labelStatus.Text = "Results cleared"
    $labelStatus.ForeColor = [System.Drawing.Color]::Blue
    $labelStats.Text = ""
    $buttonExport.Enabled = $false
    
    # Reset source statuses
    foreach ($sourceKey in $script:DataSources.Keys) {
        Update-SourceStatus -SourceKey $sourceKey -Status "Not Queried" -Color ([System.Drawing.Color]::Gray)
    }
})

$buttonExport.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv"
    $saveFileDialog.Title = "Export Vulnerability Report"
    $saveFileDialog.FileName = "SecurityUpdates_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $saveFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    
    if ($saveFileDialog.ShowDialog() -eq "OK") {
        try {
            $exportData = @()
            foreach ($row in $dataGridResults.Rows) {
                if ($row.Cells["Product"].Value) {
                    $exportData += [PSCustomObject]@{
                        Product = $row.Cells["Product"].Value
                        CVE = $row.Cells["CVE"].Value
                        Severity = $row.Cells["Severity"].Value
                        Score = $row.Cells["Score"].Value
                        Description = $row.Cells["Description"].Value
                        Published = $row.Cells["Published"].Value
                        Source = $row.Cells["Source"].Value
                        Status = $row.Cells["Status"].Value
                    }
                }
            }
            $exportData | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation
            $labelStatus.Text = "Report exported to $($saveFileDialog.FileName)"
            $labelStatus.ForeColor = [System.Drawing.Color]::Green
        } catch {
            $labelStatus.Text = "Export error: $($_.Exception.Message)"
            $labelStatus.ForeColor = [System.Drawing.Color]::Red
        }
    }
})

$buttonHelp.Add_Click({
    $helpForm = New-Object System.Windows.Forms.Form
    $helpForm.Text = "Help - Vulnerability Monitor (VULMON) v$script:AppVersion"
    $helpForm.Size = '800,700'
    $helpForm.StartPosition = "CenterParent"
    $helpForm.FormBorderStyle = "FixedDialog"
    $helpForm.MaximizeBox = $false
    
    $helpTextBox = New-Object System.Windows.Forms.TextBox
    $helpTextBox.Multiline = $true
    $helpTextBox.ReadOnly = $true
    $helpTextBox.Dock = "Fill"
    $helpTextBox.ScrollBars = "Vertical"
    $helpTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    
    $helpText = @"
VULNERABILITY MONITOR (VULMON) v$script:AppVersion
API-Based Vulnerability Monitoring

══════════════════════════════════════════════════════════════════

DATA SOURCES & STATUS INDICATORS

The tool queries three official APIs and shows real-time status:

✓ Active      - API queried successfully, data retrieved
⚠ Limited     - Partial data or degraded service
✗ Error       - Query failed (check connectivity/rate limits)
Not Queried   - API not yet used in this session

PRIMARY SOURCE:
• NIST NVD (National Vulnerability Database)
  - Official US Government CVE database
  - Most comprehensive vulnerability data
  - All CVEs from all vendors
  - Website: https://nvd.nist.gov/
  
ENRICHMENT SOURCE:
• CIRCL CVE Search
  - Fast CVE detail lookup
  - Supplementary vulnerability information
  - Website: https://cve.circl.lu/
  - NOTE: Use the checkbox to enable this source. It is
    slower as it queries every CVE found.

OPTIONAL SOURCE:
• Microsoft MSRC (Security Response Center)
  - Official Microsoft security bulletins
  - Enhanced Windows/Office monitoring
  - Requires PowerShell module installation
  - Website: https://msrc.microsoft.com/

══════════════════════════════════════════════════════════════════

SOURCE COLUMN IN RESULTS

Each vulnerability shows which API provided the data:
• "NIST NVD" - Direct from National Vulnerability Database
• "MS MSRC" - From Microsoft Security Response Center

This transparency lets you verify data provenance.

══════════════════════════════════════════════════════════════════

QUICK START

1. Enter products to monitor (one per line)
2. Set the "Start Date" and "End Date"
3. Choose your filter method:
   • (Default) Leave "Critical" and "High" checked
   • -OR- Check "Show CISA Known Exploited (KEV) Only"
     for the most urgent, in-the-wild threats.
4. (Optional) Check "Enrich CVEs with CIRCL" for more
   detailed data (this is slower).
5. Click "Check Updates"
6. Watch source status indicators update in real-time
7. Review color-coded results:
   • RED = New critical/high vulnerabilities
   • PINK = Existing critical vulnerabilities
   • YELLOW = High severity
   • WHITE = Medium/low severity

══════════════════════════════════════════════════════════════════

SEARCH FILTERS EXPLAINED

• Critical / High: Filters by theoretical severity
  (CVSS score). This shows what *could* be bad.

• Show CISA KEV Only: Filters by real-world threat.
  Shows only vulnerabilities that CISA has confirmed
  are actively being used in attacks. This is the
  most urgent filter. When checked, it overrides
  the Critical/High filter and skips the MSRC query
  (as MSRC does not support KEV filtering).

══════════════════════════════════════════════════════════════════

NVD API KEY (OPTIONAL BUT RECOMMENDED)

Why get an API key?
• Increases rate limit from 5 to 50 requests per 30 seconds
• Completely free (5-minute signup)
• Faster searches when monitoring many products

How to get:
1. Click "Get a free NVD API key" link
2. Fill out simple form (name, email, org)
3. Receive key via email
4. Paste into "NVD API Key" field
5. Click "Save Key"

══════════════════════════════════════════════════════════════════

VERSION HISTORY

v3.4 (This version)
     - Added CISA KEV (Known Exploited) filter
     - Added "Start Date" / "End Date" range
     - Added Critical/High severity filters
     - Fixed MSRC module parameter errors
     - Fixed MSRC module install path (OneDrive)
v3.3 - Added optional CIRCL enrichment checkbox
     - Fixed UI layout for Data Sources box
     - Fixed product list loading line-ending bug
v3.2 - Enhanced API source display
     - Real-time status indicators
     - Source transparency in UI and results
v3.1 - Fixed UI layout, added import/export
v3.0 - Complete rewrite using official APIs
"@
    
    $helpTextBox.Text = $helpText
    $helpForm.Controls.Add($helpTextBox)
    $helpForm.ShowDialog()
})

# Initialize source statuses on form load
$form.Add_Shown({
    # Also add our custom module path to the search path on load
    # This ensures Get-Module finds the module if it was installed in our local path
    $localModulePath = Join-Path -Path $appDataPath -ChildPath "Modules"
    if (Test-Path $localModulePath) {
        $env:PSModulePath = "$localModulePath;$($env:PSModulePath)"
    }

    # Check if MSRC module is installed
    if (Get-Module -ListAvailable -Name MsrcSecurityUpdates) {
        Update-SourceStatus -SourceKey "MSRC" -Status "✓ Available" -Color ([System.Drawing.Color]::DarkGreen)
    }
})

# Show form
$form.ShowDialog()
