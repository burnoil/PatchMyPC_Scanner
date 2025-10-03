# Windows Security Update Checker GUI using PatchMyPC Feed
# Version 2.4.0 - Final Parser Fix

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO

# ===== FILE PATHS =====
$appDataPath = Join-Path -Path $env:APPDATA -ChildPath "PMPC-Scanner"
if (-not (Test-Path $appDataPath)) {
    try {
        New-Item -Path $appDataPath -ItemType Directory -ErrorAction Stop | Out-Null
    } catch {
        [System.Windows.Forms.MessageBox]::Show("CRITICAL ERROR: Could not create the application data directory at '$appDataPath'. Please check permissions. The application will now exit.", "Initialization Error", "OK", "Error")
        exit
    }
}
$stateFilePath = Join-Path -Path $appDataPath -ChildPath "previous_scan_results.json"
$acknowledgedFilePath = Join-Path -Path $appDataPath -ChildPath "acknowledged_items.json"

# ===== CONFIGURATION =====
$script:AppVersion = "2.4.0"
$script:pageCache = @{}
$script:cvssCache = @{} # Cache for CVE scores
$script:cacheTimeout = 300

# ===== HELPER FUNCTIONS =====

function Invoke-WebRequestWithRetry {
    param(
        [string]$Uri,
        [hashtable]$Headers,
        [int]$MaxRetries = 3,
        [int]$TimeoutSec = 30
    )
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
            return $response
        } catch {
            $lastError = $_
            if ($attempt -lt $MaxRetries) {
                $waitTime = [Math]::Pow(2, $attempt)
                Write-Warning "Attempt $attempt failed for $Uri. Retrying in $waitTime seconds..."
                Start-Sleep -Seconds $waitTime
            } else {
                Write-Error "Failed to fetch $Uri after $MaxRetries attempts: $($_.Exception.Message)"
                throw $lastError
            }
        }
    }
}

function Get-CachedPage {
    param([string]$Uri, [hashtable]$Headers)
    
    $cacheKey = $Uri
    $now = Get-Date
    
    if ($script:pageCache.ContainsKey($cacheKey)) {
        $cached = $script:pageCache[$cacheKey]
        $age = ($now - $cached.Timestamp).TotalSeconds
        if ($age -lt $script:cacheTimeout) {
            return $cached.Content
        } else {
            $script:pageCache.Remove($cacheKey)
        }
    }
    
    $response = Invoke-WebRequestWithRetry -Uri $Uri -Headers $Headers
    $script:pageCache[$cacheKey] = @{Content = $response.Content; Timestamp = $now}
    return $response.Content
}

function Clear-PageCache {
    $script:pageCache.Clear()
}

function Get-CVSSScore {
    param([string]$CveId)
    
    if ($script:cvssCache.ContainsKey($CveId)) {
        return $script:cvssCache[$CveId]
    }
    try {
        $uri = "https://cve.circl.lu/api/cve/$CveId"
        $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -TimeoutSec 15
        
        $severity = "UNKNOWN"
        $score = 0
        
        # Try CVE 5.x format (newer structure)
        if ($response.containers -and $response.containers.cna -and $response.containers.cna.metrics) {
            foreach ($metric in $response.containers.cna.metrics) {
                if ($metric.cvssV3_1) {
                    $score = [double]$metric.cvssV3_1.baseScore
                    $severity = $metric.cvssV3_1.baseSeverity.ToUpper()
                    break
                } elseif ($metric.cvssV3_0) {
                    $score = [double]$metric.cvssV3_0.baseScore
                    $severity = $metric.cvssV3_0.baseSeverity.ToUpper()
                    break
                }
            }
        }
        # Try legacy CIRCL format (older CVEs)
        elseif ($response.'cvss-v3') {
            $score = [double]$response.'cvss-v3'.base_score
            $severity = $response.'cvss-v3'.base_severity.ToUpper()
        } elseif ($response.cvss) {
            $score = [double]$response.cvss
            if ($score -ge 9.0) { $severity = "CRITICAL" }
            elseif ($score -ge 7.0) { $severity = "HIGH" }
            elseif ($score -ge 4.0) { $severity = "MEDIUM" }
            elseif ($score -gt 0) { $severity = "LOW" }
        }
        
        $result = [PSCustomObject]@{ Score = $score; Severity = $severity; DisplayText = "$severity ($score)" }
        $script:cvssCache[$CveId] = $result
        return $result
    } catch {
        Write-Warning "Could not retrieve CVSS score for $CveId : $($_.Exception.Message)"
        $script:cvssCache[$CveId] = $null
        return $null
    }
}

function Save-JsonSafely {
    param([object]$Data, [string]$Path)
    try {
        if ($null -eq $Data) { return $false }
        $json = $Data | ConvertTo-Json -Depth 5 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($json)) { return $false }
        $directory = Split-Path -Path $Path -Parent
        if (-not (Test-Path $directory)) { New-Item -Path $directory -ItemType Directory -Force | Out-Null }
        $json | Out-File -FilePath $Path -Encoding UTF8 -ErrorAction Stop
        return $true
    } catch {
        Write-Warning "Failed to save JSON to $Path : $($_.Exception.Message)"
        return $false
    }
}

function Load-JsonSafely {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) { return $null }
        $content = Get-Content -Path $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content)) { return $null }
        return ($content | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Write-Warning "Failed to load JSON from $Path : $($_.Exception.Message)"
        return $null
    }
}

function Get-NormalizedSoftwareName {
    param([string]$Name)
    $normalizations = @{
        'Microsoft Visual Studio Code' = 'Visual Studio Code'; 'Visual Studio Code' = 'Visual Studio Code'
        'Adobe Acrobat Reader DC' = 'Adobe Acrobat'; 'Adobe Acrobat DC' = 'Adobe Acrobat'; 'Adobe Reader' = 'Adobe Acrobat'
        'Adobe Acrobat Reader' = 'Adobe Acrobat'; 'Acrobat Reader' = 'Adobe Acrobat'; 'Acrobat DC' = 'Adobe Acrobat'
        'Adobe Acrobat Classic' = 'Adobe Acrobat'; 'Git for Windows' = 'Git'; 'Git' = 'Git'
        '7-Zip' = '7-Zip'; '7Zip' = '7-Zip'
    }
    if ($normalizations.ContainsKey($Name)) { return $normalizations[$Name] }
    return $Name
}

function Get-DownloadUrl {
    param([string]$SoftwareName)
    $vscodeUrl = 'https://code.visualstudio.com/sha/download?build=stable"&"os=win32-x64'
    $downloadUrls = @{
        'Google Chrome' = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
        'Mozilla Firefox ESR' = 'https://www.mozilla.org/en-US/firefox/all/desktop-esr/win64-msi/en-US/'
        'Mozilla Firefox' = 'https://www.mozilla.org/firefox/download/'
        'Visual Studio Code' = $vscodeUrl
        'Microsoft Visual Studio Code' = $vscodeUrl
        '7-Zip' = 'https://www.7-zip.org/download.html'; 'Notepad++' = 'https://notepad-plus-plus.org/downloads/'
        'Git for Windows' = 'https://git-scm.com/download/win'; 'Git' = 'https://git-scm.com/download/win'
    }
    if ($downloadUrls.ContainsKey($SoftwareName)) { return $downloadUrls[$SoftwareName] }
    return $null
}

function Get-SoftwareSearchTerms {
    param([string]$Software)
    $searchTerms = @($Software)
    switch ($Software) {
        'Microsoft Visual Studio Code' { $searchTerms += 'Visual Studio Code' }
        'Adobe Acrobat Reader' { $searchTerms += @('Adobe Acrobat Reader DC', 'Adobe Acrobat DC', 'Adobe Reader', 'Adobe Acrobat', 'Acrobat Reader', 'Acrobat DC', 'Adobe Acrobat Classic') }
        'Git for Windows' { $searchTerms += 'Git' }
        '7-Zip' { $searchTerms += @('7Zip') }
        'VMware Tools' { $searchTerms += @('VMware Tools 12.x', 'VMware Tools 13.x', 'VMware Tools Latest') }
    }
    return $searchTerms
}

function Test-ShouldIncludeArchitecture {
    param([string]$Architecture)
    if ($Architecture -notmatch 'x64') { return $false }
    $excludeLanguages = @(
        'de-DE', 'de', 'fr-FR', 'fr', 'es-ES', 'es-AR', 'es-MX', 'es-CL', 'es-CO', 'es', 'it-IT', 'it', 'pt-PT', 'pt-BR', 'pt', 
        'nl-NL', 'nl', 'da-DK', 'da', 'sv-SE', 'sv', 'nb-NO', 'nb', 'fi-FI', 'fi', 'pl-PL', 'pl', 'cs-CZ', 'cs', 'hu-HU', 'hu', 
        'ru-RU', 'ru', 'ja-JP', 'ja', 'ko-KR', 'ko', 'zh-CN', 'zh-TW', 'zh', 'ar-SA', 'ar', 'he-IL', 'he', 'tr-TR', 'tr', 
        'el-GR', 'el', 'uk-UA', 'uk', 'MUI', 'ML', 'en-GB', 'en-CA', 'en-AU', 'en-NZ', 'en-IE'
    )
    foreach ($lang in $excludeLanguages) {
        if ($Architecture -match "\b$([regex]::Escape($lang))\b") { return $false }
    }
    return $true
}

function Extract-UpdateDetails {
    param([string]$PageContent, [int]$MatchIndex, [int]$SearchRadius = 3000)
    
    $startIndex = [Math]::Max(0, $MatchIndex - 100)
    $afterMatch = $PageContent.Substring($MatchIndex)
    
    # For Chrome-style entries, we need to look past multiple <li><strong>Software Version (Arch)</strong></li> entries
    # Find the content block that contains the actual details
    $detailsBlockPattern = '(?:<ul>|<li><a[^>]*>Release Notes)'
    $detailsStart = [regex]::Match($afterMatch, $detailsBlockPattern)
    
    if ($detailsStart.Success) {
        $fromDetails = $afterMatch.Substring($detailsStart.Index)
        
        # Find the end of this software's section (next software or end of list)
        $endPatterns = @(
            '</ul>\s*</li>\s*<li>\s*<strong>',  # Next software entry
            '</ul>\s*</li>\s*</ul>'              # End of software list
        )
        
        $earliestEnd = $fromDetails.Length
        foreach ($pattern in $endPatterns) {
            $endMatch = [regex]::Match($fromDetails, $pattern)
            if ($endMatch.Success -and $endMatch.Index -lt $earliestEnd) {
                $earliestEnd = $endMatch.Index
            }
        }
        
        $endOffset = $detailsStart.Index + $earliestEnd
    } else {
        # Fallback to searching within radius
        $endOffset = [Math]::Min($SearchRadius, $afterMatch.Length)
    }
    
    $actualEndIndex = $MatchIndex + $endOffset
    $updateBlock = $PageContent.Substring($startIndex, $actualEndIndex - $startIndex)
    
    # Extract CVEs from the entire block (handles Chrome's multi-variant structure)
    $cvePattern = 'CVE-\d{4}-\d{4,7}'
    $cves = [regex]::Matches($updateBlock, $cvePattern) | 
            ForEach-Object { $_.Value } | 
            Select-Object -Unique | 
            Sort-Object
    
    # Mark as security update if ANY CVEs found
    $isSecurityUpdate = $cves.Count -gt 0
    
    return @{CVEs = $cves; IsSecurityUpdate = $isSecurityUpdate}
}

function Get-PatchMyPCUpdates {
    param(
        [string[]]$SoftwareList,
        [int]$DaysBack,
        [string]$FilterType = "All Updates"
    )
    
    $results = @()
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        $labelStatus.Text = "Downloading PatchMyPC catalog feed..."
        $progressBar.Visible = $true
        $progressBar.Value = 0
        $form.Refresh()
        
        $headers = @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }

        $validCatalogUrls = @()
        $pagesToScan = [Math]::Min(15, [Math]::Ceiling($DaysBack / 30) + 1)
        $stopPaging = $false
        
        for ($page = 1; $page -le $pagesToScan; $page++) {
            if ($stopPaging) { break }
            $feedUri = "https://patchmypc.com/catalog-release/feed/?paged=$page"
            try {
                $xmlContent = Invoke-WebRequest -Uri $feedUri -Headers $headers -UseBasicParsing
                [xml]$rss = $xmlContent.Content
                $items = $rss.rss.channel.item
                if (-not $items) { Write-Warning "No more items found on feed page $page. Stopping."; break }
                foreach ($item in $items) {
                    $catalogDate = [datetime]$item.pubDate
                    if ($catalogDate -ge $cutoffDate) {
                        $validCatalogUrls += @{Url = $item.link; Date = $catalogDate}
                    } else { $stopPaging = $true }
                }
            } catch { Write-Warning "Could not fetch catalog feed page $page. It might be the last page."; break }
        }
        
        if ($validCatalogUrls.Count -eq 0) { throw "No catalog updates found within the specified date range." }
        
        $totalPages = $validCatalogUrls.Count
        $progressBar.Maximum = $totalPages
        $processedPages = 0
        
        foreach ($catalogInfo in $validCatalogUrls | Sort-Object -Property @{Expression="Date"} -Descending) {
            $processedPages++
            $progressBar.Value = $processedPages
            $labelStatus.Text = "Checking catalog page $processedPages of $totalPages..."
            $form.Refresh()
            $catalogUrl = $catalogInfo.Url
            $catalogDate = $catalogInfo.Date
            
            try {
                $pageContent = Get-CachedPage -Uri $catalogUrl -Headers $headers
                foreach ($software in $SoftwareList) {
                    if ([string]::IsNullOrWhiteSpace($software)) { continue }
                    $searchTerms = Get-SoftwareSearchTerms -Software $software
                    foreach ($term in $searchTerms) {
                        # Fixed pattern to match actual HTML structure
                        $pattern = '<li>\s*<strong>\s*' + [regex]::Escape($term) + '\s+((?:\d+\.)+\d+)\s*\(([^)]+)\)\s*</strong>'
                        $matches = [regex]::Matches($pageContent, $pattern, 'IgnoreCase')
Write-Host "Found $($matches.Count) matches for '$term'"
foreach ($match in $matches) {
    Write-Host "Matched: $($match.Value)"
}
                        
                        foreach ($match in $matches) {
                            $version = $match.Groups[1].Value.Trim()
                            $architecture = $match.Groups[2].Value.Trim()
                            if ($version -notmatch '^(\d+\.)+\d+$' -or -not (Test-ShouldIncludeArchitecture -Architecture $architecture)) { continue }
                            $updateDetails = Extract-UpdateDetails -PageContent $pageContent -MatchIndex $match.Index
                            $updateType = if ($updateDetails.IsSecurityUpdate) { "Security" } else { "Feature/Bug Fix" }
                            $results += [PSCustomObject]@{ Software = $software; Version = $version; UpdateType = $updateType; Architecture = $architecture; CVEs = ($updateDetails.CVEs -join ", "); Published = $catalogDate.ToString("yyyy-MM-dd") }
                        }
                    }
                }
            } catch { Write-Warning "Error processing $catalogUrl : $($_.Exception.Message)" }
        }
        
        $labelStatus.Text = "Completed checking $totalPages pages, found $($results.Count) updates."
        
        if ($results.Count -gt 0) {
            $labelStatus.Text = "Fetching CVE severity scores..."
            $form.Refresh()
            $updatesWithSeverity = foreach ($result in $results) {
                $highestSeverityValue = -1; $highestSeverityObject = $null
                if (-not [string]::IsNullOrWhiteSpace($result.CVEs)) {
                    foreach ($cve in ($result.CVEs -split ',\s*')) {
                        $cvss = Get-CVSSScore -CveId $cve
                        if ($null -ne $cvss) {
                            $severityValue = switch ($cvss.Severity) { "CRITICAL" { 4 }; "HIGH" { 3 }; "MEDIUM" { 2 }; "LOW" { 1 }; default { 0 } }
                            if ($severityValue -gt $highestSeverityValue) { $highestSeverityValue = $severityValue; $highestSeverityObject = $cvss }
                        }
                    }
                }
                $severityDisplay = if ($null -eq $highestSeverityObject -or [string]::IsNullOrWhiteSpace($highestSeverityObject.DisplayText)) { 'N/A' } else { $highestSeverityObject.DisplayText }
                $result | Add-Member -MemberType NoteProperty -Name "Severity" -Value $severityDisplay
                $result | Add-Member -MemberType NoteProperty -Name "SeverityScore" -Value $highestSeverityValue
                $result
            }
            $results = $updatesWithSeverity
            $mergedResults = @{}
            foreach ($result in $results) {
                $normalizedArch = 'other'
                if ($result.Architecture -like '*x64*') { $normalizedArch = 'x64' }
                elseif ($result.Architecture -like '*x86*') { $normalizedArch = 'x86' }
                $mergeKey = "$($result.Software)-$($result.Version)-$normalizedArch"
                if ($mergedResults.ContainsKey($mergeKey)) {
                    $existing = $mergedResults[$mergeKey]
                    $finalUpdateType = if ($existing.UpdateType -eq "Security" -or $result.UpdateType -eq "Security") { "Security" } else { "Feature/Bug Fix" }
                    $allCVEs = ($existing.CVEs -split ',\s*' + $result.CVEs -split ',\s*') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique | Sort-Object
                    $finalPublished = if ([datetime]$result.Published -lt [datetime]$existing.Published) { $result.Published } else { $existing.Published }
                    $finalArchitecture = ($existing.Architecture.Split([string[]]', ', [System.StringSplitOptions]::RemoveEmptyEntries) + $result.Architecture) | Select-Object -Unique | Sort-Object
                    $finalSeverity = if ($result.SeverityScore -gt $existing.SeverityScore) { $result.Severity } else { $existing.Severity }
                    $finalSeverityScore = [Math]::Max($result.SeverityScore, $existing.SeverityScore)
                    $mergedResults[$mergeKey] = [PSCustomObject]@{ Software = $existing.Software; Version = $existing.Version; UpdateType = $finalUpdateType; Architecture = $finalArchitecture -join ", "; CVEs = $allCVEs -join ", "; Severity = $finalSeverity; SeverityScore = $finalSeverityScore; Published = $finalPublished }
                } else { $mergedResults[$mergeKey] = $result }
            }
            $results = @($mergedResults.Values)
            if ($FilterType -eq "Security Only") {
                $results = @($results | Where-Object { $_.UpdateType -eq "Security" })
            } elseif ($FilterType -eq "Feature/Bug Fix Only") {
                $results = @($results | Where-Object { $_.UpdateType -eq "Feature/Bug Fix" })
            }
        }
    } catch {
        $labelStatus.Text = "Error: $($_.Exception.Message)"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
        Write-Error "Fatal error in Get-PatchMyPCUpdates: $_"
    } finally {
        $progressBar.Visible = $false
        $form.Refresh()
    }
    return $results
}

# ===== CREATE GUI =====

$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Security Update Checker (PatchMyPC) - v$script:AppVersion"
$form.Size = New-Object System.Drawing.Size(1200, 800)
$form.StartPosition = "CenterScreen"
$form.MaximizeBox = $true
$form.MinimumSize = New-Object System.Drawing.Size(1000, 600)

$labelSoftware = New-Object System.Windows.Forms.Label; $labelSoftware.Location = '10,10'; $labelSoftware.Size = '200,20'; $labelSoftware.Text = "Windows Software to Check:"; $form.Controls.Add($labelSoftware)
$textboxSoftware = New-Object System.Windows.Forms.TextBox; $textboxSoftware.Location = '10,35'; $textboxSoftware.Size = '400,100'; $textboxSoftware.Multiline = $true; $textboxSoftware.ScrollBars = "Vertical"; $textboxSoftware.Text = "Google Chrome`nMozilla Firefox ESR`n7-Zip`nNotepad++`nMicrosoft Visual Studio Code`nGit for Windows`nOracle Java`nPython`nNode.js`nWinSCP"; $form.Controls.Add($textboxSoftware)
$buttonLoadFile = New-Object System.Windows.Forms.Button; $buttonLoadFile.Location = '10,140'; $buttonLoadFile.Size = '120,25'; $buttonLoadFile.Text = "Load from File..."; $buttonLoadFile.BackColor = [System.Drawing.Color]::LightSkyBlue; $form.Controls.Add($buttonLoadFile)
$checkboxAutoRefresh = New-Object System.Windows.Forms.CheckBox; $checkboxAutoRefresh.Location = '140,143'; $checkboxAutoRefresh.Size = '90,20'; $checkboxAutoRefresh.Text = "Auto-refresh:"; $form.Controls.Add($checkboxAutoRefresh)
$comboAutoRefreshInterval = New-Object System.Windows.Forms.ComboBox; $comboAutoRefreshInterval.Location = '230,141'; $comboAutoRefreshInterval.Size = '90,25'; $comboAutoRefreshInterval.DropDownStyle = "DropDownList"; $comboAutoRefreshInterval.Items.AddRange(@("1 hour", "2 hours", "4 hours")); $comboAutoRefreshInterval.SelectedIndex = 0; $comboAutoRefreshInterval.Enabled = $false; $form.Controls.Add($comboAutoRefreshInterval)
$labelNextRefresh = New-Object System.Windows.Forms.Label; $labelNextRefresh.Location = '330,143'; $labelNextRefresh.Size = '200,20'; $labelNextRefresh.Text = ""; $labelNextRefresh.ForeColor = [System.Drawing.Color]::Gray; $form.Controls.Add($labelNextRefresh)
$labelDate = New-Object System.Windows.Forms.Label; $labelDate.Location = '430,10'; $labelDate.Size = '150,20'; $labelDate.Text = "Check Period (Days Back):"; $form.Controls.Add($labelDate)
$numericDaysBack = New-Object System.Windows.Forms.NumericUpDown; $numericDaysBack.Location = '430,35'; $numericDaysBack.Size = '80,25'; $numericDaysBack.Minimum = 1; $numericDaysBack.Maximum = 365; $numericDaysBack.Value = 30; $form.Controls.Add($numericDaysBack)
$labelDaysHelp = New-Object System.Windows.Forms.Label; $labelDaysHelp.Location = '520,37'; $labelDaysHelp.Size = '150,20'; $labelDaysHelp.Text = "days (1-365)"; $labelDaysHelp.ForeColor = [System.Drawing.Color]::Gray; $form.Controls.Add($labelDaysHelp)
$labelFilter = New-Object System.Windows.Forms.Label; $labelFilter.Location = '430,65'; $labelFilter.Size = '100,20'; $labelFilter.Text = "Filter by Type:"; $form.Controls.Add($labelFilter)
$comboFilter = New-Object System.Windows.Forms.ComboBox; $comboFilter.Location = '540,63'; $comboFilter.Size = '120,25'; $comboFilter.DropDownStyle = "DropDownList"; $comboFilter.Items.AddRange(@("All Updates", "Security Only", "Feature/Bug Fix Only")); $comboFilter.SelectedIndex = 0; $form.Controls.Add($comboFilter)
$buttonCheck = New-Object System.Windows.Forms.Button; $buttonCheck.Location = '680,35'; $buttonCheck.Size = '120,30'; $buttonCheck.Text = "Check Updates"; $buttonCheck.BackColor = [System.Drawing.Color]::LightBlue; $buttonCheck.Anchor = "Top,Left"; $form.Controls.Add($buttonCheck)
$buttonClear = New-Object System.Windows.Forms.Button; $buttonClear.Location = '810,35'; $buttonClear.Size = '120,30'; $buttonClear.Text = "Clear Results"; $buttonClear.BackColor = [System.Drawing.Color]::LightGray; $buttonClear.Anchor = "Top,Left"; $form.Controls.Add($buttonClear)
$buttonExport = New-Object System.Windows.Forms.Button; $buttonExport.Location = '680,70'; $buttonExport.Size = '120,30'; $buttonExport.Text = "Export Results"; $buttonExport.BackColor = [System.Drawing.Color]::LightGreen; $buttonExport.Enabled = $false; $buttonExport.Anchor = "Top,Left"; $form.Controls.Add($buttonExport)
$buttonClearHistory = New-Object System.Windows.Forms.Button; $buttonClearHistory.Location = '810,70'; $buttonClearHistory.Size = '120,30'; $buttonClearHistory.Text = "Clear History"; $buttonClearHistory.BackColor = [System.Drawing.Color]::LightCoral; $buttonClearHistory.Anchor = "Top,Left"; $form.Controls.Add($buttonClearHistory)
$buttonAcknowledge = New-Object System.Windows.Forms.Button; $buttonAcknowledge.Location = '940,35'; $buttonAcknowledge.Size = '120,30'; $buttonAcknowledge.Text = "Acknowledge (0)"; $buttonAcknowledge.BackColor = [System.Drawing.Color]::LightGoldenrodYellow; $buttonAcknowledge.Enabled = $false; $buttonAcknowledge.Anchor = "Top,Left"; $form.Controls.Add($buttonAcknowledge)
$buttonRefresh = New-Object System.Windows.Forms.Button; $buttonRefresh.Location = '680,105'; $buttonRefresh.Size = '120,30'; $buttonRefresh.Text = "Test Feed"; $buttonRefresh.BackColor = [System.Drawing.Color]::LightYellow; $buttonRefresh.Anchor = "Top,Left"; $form.Controls.Add($buttonRefresh)
$buttonHelp = New-Object System.Windows.Forms.Button; $buttonHelp.Location = '940,70'; $buttonHelp.Size = '120,30'; $buttonHelp.Text = "Help / About"; $buttonHelp.BackColor = [System.Drawing.Color]::AliceBlue; $buttonHelp.Anchor = "Top,Left"; $form.Controls.Add($buttonHelp)
$progressBar = New-Object System.Windows.Forms.ProgressBar; $progressBar.Location = '10,175'; $progressBar.Size = '1160,20'; $progressBar.Style = "Continuous"; $progressBar.Visible = $false; $progressBar.Anchor = "Top,Left,Right"; $form.Controls.Add($progressBar)
$labelStatus = New-Object System.Windows.Forms.Label; $labelStatus.Location = '10,200'; $labelStatus.Size = '1160,20'; $labelStatus.Text = "Ready to check Windows software security updates from PatchMyPC"; $labelStatus.ForeColor = [System.Drawing.Color]::Blue; $labelStatus.Anchor = "Top,Left,Right"; $form.Controls.Add($labelStatus)
$labelResults = New-Object System.Windows.Forms.Label; $labelResults.Location = '10,225'; $labelResults.Size = '400,20'; $labelResults.Text = "Windows Updates from PatchMyPC:"; $labelResults.Anchor = "Top,Left"; $form.Controls.Add($labelResults)
$labelStats = New-Object System.Windows.Forms.Label; $labelStats.Location = '420,225'; $labelStats.Size = '500,20'; $labelStats.Text = ""; $labelStats.ForeColor = [System.Drawing.Color]::DarkBlue; $labelStats.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold); $labelStats.Anchor = "Top,Left"; $form.Controls.Add($labelStats)
$labelSearch = New-Object System.Windows.Forms.Label; $labelSearch.Location = '940,225'; $labelSearch.Size = '50,20'; $labelSearch.Text = "Filter:"; $labelSearch.Anchor = "Top,Right"; $form.Controls.Add($labelSearch)
$textboxSearch = New-Object System.Windows.Forms.TextBox; $textboxSearch.Location = '990,222'; $textboxSearch.Size = '180,20'; $textboxSearch.Anchor = "Top,Right"; $form.Controls.Add($textboxSearch)

$dataGridResults = New-Object System.Windows.Forms.DataGridView; $dataGridResults.Location = '10,250'; $dataGridResults.Size = '1160,455'; $dataGridResults.Font = New-Object System.Drawing.Font("Segoe UI", 9); $dataGridResults.AllowUserToAddRows = $false; $dataGridResults.AllowUserToDeleteRows = $false; $dataGridResults.ReadOnly = $true; $dataGridResults.AutoSizeColumnsMode = "Fill"; $dataGridResults.SelectionMode = "FullRowSelect"; $dataGridResults.MultiSelect = $true; $dataGridResults.RowHeadersVisible = $false; $dataGridResults.Anchor = "Top,Bottom,Left,Right"; $dataGridResults.AllowUserToOrderColumns = $true; $dataGridResults.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold); $dataGridResults.EnableHeadersVisualStyles = $false; $dataGridResults.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::LightGray

$colSoftware = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colSoftware.Name = "Software"; $colSoftware.HeaderText = "Software"; $colSoftware.FillWeight = 20; $dataGridResults.Columns.Add($colSoftware)
$colVersion = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colVersion.Name = "Version"; $colVersion.HeaderText = "Version"; $colVersion.FillWeight = 12; $dataGridResults.Columns.Add($colVersion)
$colType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colType.Name = "UpdateType"; $colType.HeaderText = "Update Type"; $colType.FillWeight = 10; $dataGridResults.Columns.Add($colType)
$colArchitecture = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colArchitecture.Name = "Architecture"; $colArchitecture.HeaderText = "Architecture"; $colArchitecture.FillWeight = 8; $dataGridResults.Columns.Add($colArchitecture)
$colCVEs = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colCVEs.Name = "CVEs"; $colCVEs.HeaderText = "CVE IDs"; $colCVEs.FillWeight = 15; $dataGridResults.Columns.Add($colCVEs)
$colSeverity = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colSeverity.Name = "Severity"; $colSeverity.HeaderText = "Severity"; $colSeverity.FillWeight = 10; $dataGridResults.Columns.Add($colSeverity)
$colPublished = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colPublished.Name = "Published"; $colPublished.HeaderText = "Published"; $colPublished.FillWeight = 10; $dataGridResults.Columns.Add($colPublished)
$colStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colStatus.Name = "Status"; $colStatus.HeaderText = "Status"; $colStatus.FillWeight = 8; $dataGridResults.Columns.Add($colStatus)
$form.Controls.Add($dataGridResults)

$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip; $menuItemDownload = New-Object System.Windows.Forms.ToolStripMenuItem; $menuItemDownload.Text = "Open Download Page"; $contextMenu.Items.Add($menuItemDownload); $dataGridResults.ContextMenuStrip = $contextMenu

$labelLastUpdated = New-Object System.Windows.Forms.Label; $labelLastUpdated.Location = '10,715'; $labelLastUpdated.Size = '400,20'; $labelLastUpdated.Text = "Last checked: Never"; $labelLastUpdated.ForeColor = [System.Drawing.Color]::Gray; $labelLastUpdated.Anchor = "Bottom,Left"; $form.Controls.Add($labelLastUpdated)
$labelHistoryDate = New-Object System.Windows.Forms.Label; $labelHistoryDate.Location = '10,735'; $labelHistoryDate.Size = '400,20'; $labelHistoryDate.Text = "Previous scan history: Not found"; $labelHistoryDate.ForeColor = [System.Drawing.Color]::Gray; $labelHistoryDate.Anchor = "Bottom,Left"; $form.Controls.Add($labelHistoryDate)
$labelAcknowledged = New-Object System.Windows.Forms.Label; $labelAcknowledged.Location = '420,715'; $labelAcknowledged.Size = '400,20'; $labelAcknowledged.Text = "Acknowledged items: 0"; $labelAcknowledged.ForeColor = [System.Drawing.Color]::Gray; $labelAcknowledged.Anchor = "Bottom,Left"; $form.Controls.Add($labelAcknowledged)
$labelLegend = New-Object System.Windows.Forms.Label; $labelLegend.Location = '420,735'; $labelLegend.Size = '600,20'; $labelLegend.Text = "Legend: Red = New | Yellow = Acknowledged"; $labelLegend.ForeColor = [System.Drawing.Color]::Gray; $labelLegend.Anchor = "Bottom,Left"; $form.Controls.Add($labelLegend)

# ===== EVENT HANDLERS =====

$menuItemDownload.Add_Click({
    if ($dataGridResults.SelectedRows.Count -gt 0) {
        $software = $dataGridResults.SelectedRows[0].Cells["Software"].Value
        $downloadUrl = Get-DownloadUrl -SoftwareName $software
        if ($downloadUrl) {
            Start-Process $downloadUrl
            $labelStatus.Text = "Attempting to open download page for '$software'..."
            $labelStatus.ForeColor = [System.Drawing.Color]::Blue
        } else {
            [System.Windows.Forms.MessageBox]::Show("No download URL available for $software", "Download Not Available", "OK", "Information")
        }
    }
})

$buttonLoadFile.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog; $openFileDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"; $openFileDialog.Title = "Select Software List File"; $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    if ($openFileDialog.ShowDialog() -eq "OK") {
        try { $textboxSoftware.Text = Get-Content -Path $openFileDialog.FileName -Raw; $labelStatus.Text = "Loaded software list from: $($openFileDialog.FileName)"; $labelStatus.ForeColor = [System.Drawing.Color]::Green }
        catch { $labelStatus.Text = "Error loading file: $($_.Exception.Message)"; $labelStatus.ForeColor = [System.Drawing.Color]::Red; [System.Windows.Forms.MessageBox]::Show("Could not load the file.`n`nError: $($_.Exception.Message)", "File Load Error", "OK", "Error") }
    }
})

$buttonCheck.Add_Click({
    $dataGridResults.Rows.Clear(); $buttonExport.Enabled = $false; $buttonAcknowledge.Enabled = $false; $labelStatus.Text = "Starting update check..."; $labelStats.Text = ""; $form.Refresh()
    $acknowledgedItems = @{}; $ackData = Load-JsonSafely -Path $acknowledgedFilePath; if ($null -ne $ackData) { foreach ($item in $ackData) { $key = "$($item.Software)-$($item.Version)-$($item.Architecture)"; $acknowledgedItems[$key] = $item.AcknowledgedDate } }; $labelAcknowledged.Text = "Acknowledged items: $($acknowledgedItems.Count)"
    $historyExists = $false; $previousResults = Load-JsonSafely -Path $stateFilePath; if ($null -ne $previousResults) { $historyDate = (Get-Item $stateFilePath).LastWriteTime; $labelHistoryDate.Text = "Previous scan history from: $($historyDate.ToString('yyyy-MM-dd HH:mm:ss'))"; $historyExists = $true } else { $labelHistoryDate.Text = "Previous scan history: Not found" }
    $previousKeys = @{}; if ($previousResults) { foreach ($item in $previousResults) { $key = "$($item.Software)-$($item.Version)-$($item.Architecture)"; if (-not $previousKeys.ContainsKey($key)) { $previousKeys.Add($key, $true) } } }
    $softwareList = $textboxSoftware.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }; $daysBack = [int]$numericDaysBack.Value; $filterType = $comboFilter.SelectedItem.ToString()
    if ($softwareList.Count -eq 0) { $labelStatus.Text = "Error: No valid software names provided"; $labelStatus.ForeColor = [System.Drawing.Color]::Red; return }
    $results = Get-PatchMyPCUpdates -SoftwareList $softwareList -DaysBack $daysBack -FilterType $filterType
    if ($results.Count -eq 0) { $labelStatus.Text = "No updates found matching criteria."; $labelStatus.ForeColor = [System.Drawing.Color]::Orange; $labelStats.Text = "" } 
    else {
        $newCount = 0; $acknowledgedCount = 0
        foreach ($result in $results) {
            try {
                $currentKey = "$($result.Software)-$($result.Version)-$($result.Architecture)"
                $status = "Previously Seen"
                # Base row color on Severity
                switch ($result.Severity) {
                    { $_ -like 'CRITICAL*' } { $rowColor = [System.Drawing.Color]::FromArgb(255, 192, 203) } # LightPink
                    { $_ -like 'HIGH*' }     { $rowColor = [System.Drawing.Color]::FromArgb(255, 224, 192) } # LightOrange (custom)
                    { $_ -like 'MEDIUM*' }   { $rowColor = [System.Drawing.Color]::FromArgb(255, 255, 192) } # LightYellow
                    default                 { $rowColor = [System.Drawing.Color]::White }
                }
                # Status colors (New/Acknowledged) override severity colors
                if ($acknowledgedItems.ContainsKey($currentKey)) {
                    $status = "Acknowledged"
                    $rowColor = [System.Drawing.Color]::LightGoldenrodYellow
                    $acknowledgedCount++
                } elseif ($historyExists -and (-not $previousKeys.ContainsKey($currentKey))) {
                    $status = "NEW"
                    $rowColor = [System.Drawing.Color]::LightCoral
                    $newCount++
                }
                $rowIndex = $dataGridResults.Rows.Add($result.Software, $result.Version, $result.UpdateType, $result.Architecture, $result.CVEs, $result.Severity, $result.Published, $status)
                $dataGridResults.Rows[$rowIndex].DefaultCellStyle.BackColor = $rowColor
            } catch { $labelStatus.Text = "Error adding row: $($_.Exception.Message)"; $labelStatus.ForeColor = [System.Drawing.Color]::Red }
        }
        Save-JsonSafely -Data $results -Path $stateFilePath | Out-Null
        $securityCount = 0; $totalCVEs = 0; $uniqueSoftware = @{}; $criticalCount = 0
        foreach ($result in $results) {
            if ($result.UpdateType -eq "Security") { $securityCount++ }
            if (-not [string]::IsNullOrWhiteSpace($result.CVEs)) { $totalCVEs++ }
            if ($result.Severity -like 'CRITICAL*') { $criticalCount++ }
            if (-not $uniqueSoftware.ContainsKey($result.Software)) { $uniqueSoftware[$result.Software] = $true }
        }
        $labelStats.Text = "Summary: $criticalCount Critical | $securityCount Security Updates | $($uniqueSoftware.Count) Products"
        $statusMsg = "Successfully loaded $($results.Count) updates"; if ($newCount -gt 0) { $statusMsg += " ($newCount NEW)" }; if ($acknowledgedCount -gt 0) { $statusMsg += " ($acknowledgedCount acknowledged)" }
        $labelStatus.Text = $statusMsg; $labelStatus.ForeColor = [System.Drawing.Color]::Green; $buttonExport.Enabled = $true
    }
})

$buttonClear.Add_Click({ $dataGridResults.Rows.Clear(); Clear-PageCache; $labelStatus.Text = "Results and cache cleared"; $labelStatus.ForeColor = [System.Drawing.Color]::Blue; $labelStats.Text = ""; $buttonExport.Enabled = $false; $buttonAcknowledge.Enabled = $false })
$buttonAcknowledge.Add_Click({
    if ($dataGridResults.SelectedRows.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show("Please select one or more items to acknowledge.", "No Selection", "OK", "Information"); return }
    $acknowledgedItems = @(); $ackData = Load-JsonSafely -Path $acknowledgedFilePath; if ($null -ne $ackData) { $acknowledgedItems = @($ackData) }
    $existingKeys = @{}; foreach ($item in $acknowledgedItems) { $key = "$($item.Software)-$($item.Version)-$($item.Architecture)"; $existingKeys[$key] = $true }
    $newlyAcknowledged = 0; $alreadyAcknowledged = 0
    foreach ($selectedRow in $dataGridResults.SelectedRows) {
        $software = $selectedRow.Cells["Software"].Value; $version = $selectedRow.Cells["Version"].Value; $architecture = $selectedRow.Cells["Architecture"].Value; $key = "$software-$version-$architecture"
        if ($existingKeys.ContainsKey($key)) { $alreadyAcknowledged++; continue }
        $acknowledgedItems += [PSCustomObject]@{ Software = $software; Version = $version; Architecture = $architecture; AcknowledgedDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') }
        $existingKeys[$key] = $true; $selectedRow.Cells["Status"].Value = "Acknowledged"; $selectedRow.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightGoldenrodYellow; $newlyAcknowledged++
    }
    if (Save-JsonSafely -Data $acknowledgedItems -Path $acknowledgedFilePath) {
        $statusMsg = ""; if ($newlyAcknowledged -gt 0) { $statusMsg = "Acknowledged $newlyAcknowledged item(s)" }; if ($alreadyAcknowledged -gt 0) { if ($statusMsg) { $statusMsg += "; " }; $statusMsg += "$alreadyAcknowledged already acknowledged" }
        $labelStatus.Text = $statusMsg; $labelStatus.ForeColor = [System.Drawing.Color]::Green; $labelAcknowledged.Text = "Acknowledged items: $($acknowledgedItems.Count)"
    } else { $labelStatus.Text = "Error acknowledging items"; $labelStatus.ForeColor = [System.Drawing.Color]::Red }
})

$dataGridResults.Add_SelectionChanged({ $selectedCount = $dataGridResults.SelectedRows.Count; if ($selectedCount -gt 0) { $buttonAcknowledge.Enabled = $true; $buttonAcknowledge.Text = "Acknowledge ($selectedCount)" } else { $buttonAcknowledge.Enabled = $false; $buttonAcknowledge.Text = "Acknowledge (0)" } })
$buttonClearHistory.Add_Click({
    if ([System.Windows.Forms.MessageBox]::Show("This will clear both scan history and acknowledged items. Are you sure?", "Confirm Clear All", "YesNo", "Warning") -eq "Yes") {
        $clearedItems = @()
        if (Test-Path $stateFilePath) { try { Remove-Item -Path $stateFilePath -ErrorAction Stop; $clearedItems += "scan history" } catch { $labelStatus.Text = "Error clearing scan history: $($_.Exception.Message)"; $labelStatus.ForeColor = [System.Drawing.Color]::Red; return } }
        if (Test-Path $acknowledgedFilePath) { try { Remove-Item -Path $acknowledgedFilePath -ErrorAction Stop; $clearedItems += "acknowledged items" } catch { $labelStatus.Text = "Error clearing acknowledged items: $($_.Exception.Message)"; $labelStatus.ForeColor = [System.Drawing.Color]::Red; return } }
        if ($clearedItems.Count -gt 0) { $labelStatus.Text = "Cleared: $($clearedItems -join ' and ')"; $labelStatus.ForeColor = [System.Drawing.Color]::Blue; $labelHistoryDate.Text = "Previous scan history: Not found"; $labelAcknowledged.Text = "Acknowledged items: 0" } 
        else { $labelStatus.Text = "No history or acknowledged items to clear."; $labelStatus.ForeColor = [System.Drawing.Color]::Blue }
    }
})

$buttonExport.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog; $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv"; $saveFileDialog.Title = "Save Update Report"; $saveFileDialog.FileName = "PatchMyPC_Updates_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"; $saveFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    if ($saveFileDialog.ShowDialog() -eq "OK") {
        try {
            $exportData = @(); foreach ($row in $dataGridResults.Rows) { if ($row.Cells["Software"].Value) { $exportData += [PSCustomObject]@{ Software = $row.Cells["Software"].Value; Version = $row.Cells["Version"].Value; UpdateType = $row.Cells["UpdateType"].Value; Architecture = $row.Cells["Architecture"].Value; CVEs = $row.Cells["CVEs"].Value; Severity = $row.Cells["Severity"].Value; Published = $row.Cells["Published"].Value; Status = $row.Cells["Status"].Value } } }
            $exportData | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation; $labelStatus.Text = "Results exported to $($saveFileDialog.FileName)"; $labelStatus.ForeColor = [System.Drawing.Color]::Green
        } catch { $labelStatus.Text = "Error exporting: $($_.Exception.Message)"; $labelStatus.ForeColor = [System.Drawing.Color]::Red }
    }
})

#$buttonDebug.Add_Click({ try { $testRequest = Invoke-WebRequest -Uri "https://patchmypc.com/" -TimeoutSec 10 -UseBasicParsing; $labelStatus.Text = "Debug: Successfully connected (Status: $($testRequest.StatusCode))"; $labelStatus.ForeColor = [System.Drawing.Color]::Green } catch { $labelStatus.Text = "Debug ERROR: $($_.Exception.Message)"; $labelStatus.ForeColor = [System.Drawing.Color]::Red } })
$buttonRefresh.Add_Click({ try { $headers = @{'Accept-Language' = 'en-US,en;q=0.9'; 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}; $testRequest = Invoke-WebRequest -Uri "https://patchmypc.com/category/catalog-updates/" -TimeoutSec 10 -Headers $headers -UseBasicParsing; $catalogUrls = [regex]::Matches($testRequest.Content, 'href="(https://patchmypc\.com/catalog-release/\d{4}/\d{2}-\d{2}-\d{2}/)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -First 1; $labelStatus.Text = "Test Feed: Latest catalog found: ${catalogUrls}"; $labelStatus.ForeColor = [System.Drawing.Color]::Green } catch { $labelStatus.Text = "Test Feed ERROR: $($_.Exception.Message)"; $labelStatus.ForeColor = [System.Drawing.Color]::Red } })
$buttonHelp.Add_Click({
    $helpForm = New-Object System.Windows.Forms.Form; $helpForm.Text = "Help / About - PatchMyPC Update Checker"; $helpForm.Size = '650,550'; $helpForm.StartPosition = "CenterParent"; $helpForm.FormBorderStyle = "FixedDialog"; $helpForm.MaximizeBox = $false; $helpForm.MinimizeBox = $false
    $helpTextBox = New-Object System.Windows.Forms.TextBox; $helpTextBox.Multiline = $true; $helpTextBox.ReadOnly = $true; $helpTextBox.Dock = "Fill"; $helpTextBox.ScrollBars = "Vertical"; $helpTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $helpText = "PatchMyPC Update Checker - Help`n`nVERSION: $script:AppVersion`n`nFEATURES`n- Check for security updates and CVEs`n- NEW (RED) vs Acknowledged (YELLOW) tracking`n- CVSS Severity Scoring (CRITICAL, HIGH, MEDIUM)`n- Color-coded rows for at-a-glance prioritization`n- Export to CSV, auto-refresh, real-time search`n`nHOW TO USE`n1. Enter software names (one per line)`n2. Set days back to check (1-365)`n3. Click 'Check Updates'`n4. Critical/High severity items will be colored red/orange`n5. NEW items appear in bright red`n`nIMPROVEMENTS IN v2.3.0`n- Switched to reliable RSS feed for data`n- Integrated CVSS severity scoring and color-coding`n- Smarter merging for duplicate version numbers`n- Parser fixes for strict environments`n`nData Source: PatchMyPC (https://patchmypc.com) & CVE Details: CIRCL (https://cve.circl.lu)"
    $helpTextBox.Text = $helpText.Replace("`n", [Environment]::NewLine); $helpForm.Controls.Add($helpTextBox); $helpForm.ShowDialog()
})

$buttonInspect.Add_Click({
    try {
        $labelStatus.Text = "Inspecting catalog HTML structure..."
        $form.Refresh()
        
        $headers = @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        
        # Get first catalog URL from RSS
        $feedUri = "https://patchmypc.com/catalog-release/feed/?paged=1"
        $xmlContent = Invoke-WebRequest -Uri $feedUri -Headers $headers -UseBasicParsing
        [xml]$rss = $xmlContent.Content
        $firstCatalog = $rss.rss.channel.item[0].link
        
        $labelStatus.Text = "Fetching catalog page: $firstCatalog"
        $form.Refresh()
        
        # Fetch that catalog page
        $pageContent = Invoke-WebRequest -Uri $firstCatalog -Headers $headers -UseBasicParsing
        
        # Save full HTML to desktop for inspection
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $htmlFile = Join-Path $desktopPath "PatchMyPC_Catalog_Sample.html"
        $pageContent.Content | Out-File -FilePath $htmlFile -Encoding UTF8
        
        # Also create a snippet file with Chrome context
        $searchPattern = "Chrome"
        $snippetFile = Join-Path $desktopPath "PatchMyPC_Chrome_Snippet.txt"
        $index = $pageContent.Content.IndexOf($searchPattern, [System.StringComparison]::OrdinalIgnoreCase)
        
        if ($index -gt 0) {
            # Get multiple occurrences
            $allMatches = [regex]::Matches($pageContent.Content, $searchPattern, 'IgnoreCase')
            $snippets = ""
            $count = 0
            foreach ($match in $allMatches) {
                if ($count -ge 5) { break }  # Only first 5 matches
                $start = [Math]::Max(0, $match.Index - 300)
                $length = [Math]::Min(800, $pageContent.Content.Length - $start)
                $snippet = $pageContent.Content.Substring($start, $length)
                $snippets += "`n`n========== MATCH $($count + 1) at position $($match.Index) ==========`n$snippet"
                $count++
            }
            $snippets | Out-File -FilePath $snippetFile -Encoding UTF8
            
            [System.Windows.Forms.MessageBox]::Show("Files saved to Desktop:`n`n1. PatchMyPC_Catalog_Sample.html (full page)`n2. PatchMyPC_Chrome_Snippet.txt (Chrome contexts)`n`nOpen the snippet file to see the HTML structure around Chrome entries.", "Files Saved", "OK", "Information")
            $labelStatus.Text = "HTML files saved to Desktop for inspection"
            $labelStatus.ForeColor = [System.Drawing.Color]::Green
        } else {
            $pageContent.Content | Out-File -FilePath $snippetFile -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("Chrome not found in catalog.`n`nFull HTML saved to:`n$htmlFile`n`nOpen this file to see the actual structure.", "Not Found - File Saved", "OK", "Warning")
            $labelStatus.Text = "Chrome not found - full HTML saved to Desktop"
            $labelStatus.ForeColor = [System.Drawing.Color]::Orange
        }
        
        # Try to open the snippet file
        Start-Process notepad.exe -ArgumentList $snippetFile
        
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error during inspection:`n`n$($_.Exception.Message)", "Inspection Failed", "OK", "Error")
        $labelStatus.Text = "HTML inspection failed: $($_.Exception.Message)"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
    }
})

$textboxSearch.Add_TextChanged({
    $searchText = $textboxSearch.Text; if ([string]::IsNullOrWhiteSpace($searchText)) { foreach ($row in $dataGridResults.Rows) { $row.Visible = $true } } else { foreach ($row in $dataGridResults.Rows) { $visible = $false; foreach ($cell in $row.Cells) { if ($cell.Value -and $cell.Value.ToString() -like "*$searchText*") { $visible = $true; break } }; $row.Visible = $visible } }
})

$dataGridResults.Add_CellDoubleClick({ param($sender, $e); if ($e.RowIndex -ge 0 -and $e.ColumnIndex -ge 0) { $cellValue = $dataGridResults.Rows[$e.RowIndex].Cells[$e.ColumnIndex].Value; if ($cellValue) { [System.Windows.Forms.Clipboard]::SetText($cellValue.ToString()); $labelStatus.Text = "Copied to clipboard: $cellValue"; $labelStatus.ForeColor = [System.Drawing.Color]::Green } } })

$autoRefreshTimer = New-Object System.Windows.Forms.Timer; $script:nextRefreshTime = $null
$autoRefreshTimer.Add_Tick({ $labelStatus.Text = "Auto-refresh triggered..."; $buttonCheck.PerformClick(); $interval = switch ($comboAutoRefreshInterval.SelectedItem) { "1 hour" { 1 } "2 hours" { 2 } "4 hours" { 4 } default { 1 } }; $script:nextRefreshTime = (Get-Date).AddHours($interval); $labelNextRefresh.Text = "Next refresh: $($script:nextRefreshTime.ToString('HH:mm'))" })
$checkboxAutoRefresh.Add_CheckedChanged({ if ($checkboxAutoRefresh.Checked) { $comboAutoRefreshInterval.Enabled = $true; $intervalMs = switch ($comboAutoRefreshInterval.SelectedItem) { "1 hour" { 3600000 } "2 hours" { 7200000 } "4 hours" { 14400000 } default { 3600000 } }; $autoRefreshTimer.Interval = $intervalMs; $autoRefreshTimer.Start(); $script:nextRefreshTime = (Get-Date).AddMilliseconds($intervalMs); $labelNextRefresh.Text = "Next refresh: $($script:nextRefreshTime.ToString('HH:mm'))"; $labelNextRefresh.ForeColor = [System.Drawing.Color]::Green } else { $autoRefreshTimer.Stop(); $comboAutoRefreshInterval.Enabled = $false; $labelNextRefresh.Text = ""; $script:nextRefreshTime = $null } })
$comboAutoRefreshInterval.Add_SelectedIndexChanged({ if ($checkboxAutoRefresh.Checked) { $autoRefreshTimer.Stop(); $intervalMs = switch ($comboAutoRefreshInterval.SelectedItem) { "1 hour" { 3600000 } "2 hours" { 7200000 } "4 hours" { 14400000 } default { 3600000 } }; $autoRefreshTimer.Interval = $intervalMs; $autoRefreshTimer.Start(); $script:nextRefreshTime = (Get-Date).AddMilliseconds($intervalMs); $labelNextRefresh.Text = "Next refresh: $($script:nextRefreshTime.ToString('HH:mm'))" } })

$form.ShowDialog()
