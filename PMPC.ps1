# Windows Security Update Checker GUI using PatchMyPC Feed
# Version 2.1.0 - Enhanced with improved accuracy and reliability

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
$script:AppVersion = "2.1.0"
$script:pageCache = @{}
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

function Save-JsonSafely {
    param([object]$Data, [string]$Path)
    
    try {
        if ($null -eq $Data) { return $false }
        $json = $Data | ConvertTo-Json -Depth 5 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($json)) { return $false }
        
        $directory = Split-Path -Path $Path -Parent
        if (-not (Test-Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
        
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
        'Microsoft Visual Studio Code' = 'Visual Studio Code'
        'Visual Studio Code' = 'Visual Studio Code'
        'Adobe Acrobat Reader DC' = 'Adobe Acrobat'
        'Adobe Acrobat DC' = 'Adobe Acrobat'
        'Adobe Reader' = 'Adobe Acrobat'
        'Adobe Acrobat Reader' = 'Adobe Acrobat'
        'Acrobat Reader' = 'Adobe Acrobat'
        'Acrobat DC' = 'Adobe Acrobat'
        'Adobe Acrobat Classic' = 'Adobe Acrobat'
        'Git for Windows' = 'Git'
        'Git' = 'Git'
        '7-Zip' = '7-Zip'
        '7Zip' = '7-Zip'
    }
    
    if ($normalizations.ContainsKey($Name)) { return $normalizations[$Name] }
    return $Name
}

function Get-SoftwareSearchTerms {
    param([string]$Software)
    
    $searchTerms = @($Software)
    switch ($Software) {
        'Microsoft Visual Studio Code' { $searchTerms += 'Visual Studio Code' }
        'Adobe Acrobat Reader' { 
            $searchTerms += @('Adobe Acrobat Reader DC', 'Adobe Acrobat DC', 'Adobe Reader', 'Adobe Acrobat', 'Acrobat Reader', 'Acrobat DC', 'Adobe Acrobat Classic')
        }
        'Git for Windows' { $searchTerms += 'Git' }
        '7-Zip' { $searchTerms += @('7Zip') }
    }
    return $searchTerms
}

function Test-ShouldIncludeArchitecture {
    param([string]$Architecture)
    
    if ($Architecture -notmatch 'x64') { return $false }
    
    $excludeLanguages = @(
        'de-DE', 'de', 'fr-FR', 'fr', 'es-ES', 'es-AR', 'es-MX', 'es-CL', 'es-CO', 'es', 
        'it-IT', 'it', 'pt-PT', 'pt-BR', 'pt', 'nl-NL', 'nl', 'da-DK', 'da', 'sv-SE', 'sv',
        'nb-NO', 'nb', 'fi-FI', 'fi', 'pl-PL', 'pl', 'cs-CZ', 'cs', 'hu-HU', 'hu', 'ru-RU', 'ru',
        'ja-JP', 'ja', 'ko-KR', 'ko', 'zh-CN', 'zh-TW', 'zh', 'ar-SA', 'ar', 'he-IL', 'he',
        'tr-TR', 'tr', 'el-GR', 'el', 'uk-UA', 'uk', 'MUI', 'ML', 'en-GB', 'en-CA', 'en-AU', 'en-NZ', 'en-IE'
    )
    
    foreach ($lang in $excludeLanguages) {
        if ($Architecture -match "\b$([regex]::Escape($lang))\b") { return $false }
    }
    return $true
}

function Extract-UpdateDetails {
    param([string]$PageContent, [int]$MatchIndex, [int]$SearchRadius = 1500)
    
    $startIndex = [Math]::Max(0, $MatchIndex - 300)
    $endIndex = [Math]::Min($PageContent.Length, $MatchIndex + $SearchRadius)
    $afterMatch = $PageContent.Substring($MatchIndex, $endIndex - $MatchIndex)
    
    $boundaryPatterns = @('<(?:h[23]|div class="entry")', '\n\s*\n\s*\n', '(?:^|\n)[A-Z][a-zA-Z\s]+\d+\.\d+')
    $smallestBoundary = $afterMatch.Length
    
    foreach ($pattern in $boundaryPatterns) {
        $match = [regex]::Match($afterMatch, $pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
        if ($match.Success -and $match.Index -lt $smallestBoundary -and $match.Index -gt 100) {
            $smallestBoundary = $match.Index
        }
    }
    
    if ($smallestBoundary -lt $afterMatch.Length) {
        $endIndex = $MatchIndex + $smallestBoundary
    }
    
    $updateBlock = $PageContent.Substring($startIndex, $endIndex - $startIndex)
    
    $cvePattern = 'CVE-\d{4}-\d{4,7}'
    $cves = [regex]::Matches($updateBlock, $cvePattern) | ForEach-Object { $_.Value } | Select-Object -Unique | Sort-Object
    
    $isSecurityUpdate = $false
    if ($cves.Count -gt 0) {
        $isSecurityUpdate = $true
    } else {
        $securityPatterns = @('security\s+(?:update|release|fix|patch)', 'vulnerability|vulnerabilities', 'critical\s+update', 'security\s+advisory', 'CVE-IDs?:')
        foreach ($pattern in $securityPatterns) {
            if ($updateBlock -match $pattern) {
                $isSecurityUpdate = $true
                break
            }
        }
    }
    
    return @{CVEs = $cves; IsSecurityUpdate = $isSecurityUpdate}
}

function Get-PatchMyPCUpdates {
    param([string[]]$SoftwareList, [int]$DaysBack, [string]$FilterType = "All Updates")
    
    $results = @()
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    $processedUpdates = @{}
    
    try {
        $labelStatus.Text = "Downloading PatchMyPC catalog pages..."
        $progressBar.Visible = $true
        $progressBar.Value = 0
        $form.Refresh()
        
        $headers = @{
            'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            'Accept-Language' = 'en-US,en;q=0.9'
        }
        
        $mainPageContent = Get-CachedPage -Uri "https://patchmypc.com/category/catalog-updates/" -Headers $headers
        $catalogUrls = [regex]::Matches($mainPageContent, 'href="(https://patchmypc\.com/catalog-release/\d{4}/\d{2}-\d{2}-\d{2}/)"') | 
                       ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique | Select-Object -First 15
        
        if ($catalogUrls.Count -eq 0) { throw "No catalog URLs found on main page" }
        
        $validCatalogUrls = @()
        foreach ($url in $catalogUrls) {
            if ($url -match '/(\d{4})/(\d{2})-(\d{2})-(\d{2})/') {
                try {
                    $catalogDate = Get-Date -Year ([int]$matches[1]) -Month ([int]$matches[2]) -Day ([int]$matches[3])
                    if ($catalogDate -ge $cutoffDate) {
                        $validCatalogUrls += @{Url = $url; Date = $catalogDate}
                    }
                } catch {
                    Write-Warning "Invalid date in URL: $url"
                }
            }
        }
        
        $totalPages = $validCatalogUrls.Count
        $progressBar.Maximum = $totalPages
        $processedPages = 0
        
        foreach ($catalogInfo in $validCatalogUrls) {
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
                    $normalizedName = Get-NormalizedSoftwareName -Name $software
                    
                    foreach ($term in $searchTerms) {
                        $patterns = @(
                            "$([regex]::Escape($term))\s+((?:\d+\.)+\d+)\s*\(([^)]+)\)",
                            "$([regex]::Escape($term))\s*[-–]\s*((?:\d+\.)+\d+)\s*\(([^)]+)\)"
                        )
                        
                        foreach ($pattern in $patterns) {
                            $matches = [regex]::Matches($pageContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                            
                            foreach ($match in $matches) {
                                $version = $match.Groups[1].Value.Trim()
                                $architecture = $match.Groups[2].Value.Trim()
                                
                                if ($version -notmatch '^(\d+\.)+\d+$') { continue }
                                if (-not (Test-ShouldIncludeArchitecture -Architecture $architecture)) { continue }
                                
                                $uniqueKey = "$normalizedName-$version-$architecture"
                                if ($processedUpdates.ContainsKey($uniqueKey)) { continue }
                                
                                $updateDetails = Extract-UpdateDetails -PageContent $pageContent -MatchIndex $match.Index
                                $updateType = if ($updateDetails.IsSecurityUpdate) { "Security" } else { "Feature/Bug Fix" }
                                
                                if ($FilterType -eq "Security Only" -and $updateType -ne "Security") { continue }
                                if ($FilterType -eq "Feature/Bug Fix Only" -and $updateType -ne "Feature/Bug Fix") { continue }
                                
                                $processedUpdates.Add($uniqueKey, $true)
                                
                                $results += [PSCustomObject]@{
                                    Software = $software
                                    Version = $version
                                    UpdateType = $updateType
                                    Architecture = $architecture
                                    CVEs = ($updateDetails.CVEs -join ", ")
                                    Published = $catalogDate.ToString("yyyy-MM-dd")
                                }
                            }
                        }
                    }
                }
                
                Start-Sleep -Milliseconds 250
            } catch {
                Write-Warning "Error processing $catalogUrl : $($_.Exception.Message)"
                $labelStatus.Text = "Warning: Error on page $processedPages, continuing..."
                $labelStatus.ForeColor = [System.Drawing.Color]::Orange
                $form.Refresh()
                Start-Sleep -Milliseconds 500
            }
        }
        
        $labelStatus.Text = "Completed checking $totalPages pages, found $($results.Count) updates"
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
        $labelLastUpdated.Text = "Last checked: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
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

$labelSoftware = New-Object System.Windows.Forms.Label
$labelSoftware.Location = New-Object System.Drawing.Point(10, 10)
$labelSoftware.Size = New-Object System.Drawing.Size(200, 20)
$labelSoftware.Text = "Windows Software to Check:"
$form.Controls.Add($labelSoftware)

$textboxSoftware = New-Object System.Windows.Forms.TextBox
$textboxSoftware.Location = New-Object System.Drawing.Point(10, 35)
$textboxSoftware.Size = New-Object System.Drawing.Size(400, 100)
$textboxSoftware.Multiline = $true
$textboxSoftware.ScrollBars = "Vertical"
$textboxSoftware.Text = "Google Chrome`nMozilla Firefox ESR`n7-Zip`nNotepad++`nMicrosoft Visual Studio Code`nGit for Windows`nOracle Java`nPython`nNode.js`nWinSCP"
$form.Controls.Add($textboxSoftware)

$buttonLoadFile = New-Object System.Windows.Forms.Button
$buttonLoadFile.Location = New-Object System.Drawing.Point(10, 140)
$buttonLoadFile.Size = New-Object System.Drawing.Size(120, 25)
$buttonLoadFile.Text = "Load from File..."
$buttonLoadFile.BackColor = [System.Drawing.Color]::LightSkyBlue
$form.Controls.Add($buttonLoadFile)

$labelDate = New-Object System.Windows.Forms.Label
$labelDate.Location = New-Object System.Drawing.Point(430, 10)
$labelDate.Size = New-Object System.Drawing.Size(150, 20)
$labelDate.Text = "Check Period (Days Back):"
$form.Controls.Add($labelDate)

$numericDaysBack = New-Object System.Windows.Forms.NumericUpDown
$numericDaysBack.Location = New-Object System.Drawing.Point(430, 35)
$numericDaysBack.Size = New-Object System.Drawing.Size(80, 25)
$numericDaysBack.Minimum = 1
$numericDaysBack.Maximum = 365
$numericDaysBack.Value = 30
$form.Controls.Add($numericDaysBack)

$labelDaysHelp = New-Object System.Windows.Forms.Label
$labelDaysHelp.Location = New-Object System.Drawing.Point(520, 37)
$labelDaysHelp.Size = New-Object System.Drawing.Size(150, 20)
$labelDaysHelp.Text = "days (1-365)"
$labelDaysHelp.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($labelDaysHelp)

$labelFilter = New-Object System.Windows.Forms.Label
$labelFilter.Location = New-Object System.Drawing.Point(430, 65)
$labelFilter.Size = New-Object System.Drawing.Size(100, 20)
$labelFilter.Text = "Filter by Type:"
$form.Controls.Add($labelFilter)

$comboFilter = New-Object System.Windows.Forms.ComboBox
$comboFilter.Location = New-Object System.Drawing.Point(540, 63)
$comboFilter.Size = New-Object System.Drawing.Size(120, 25)
$comboFilter.DropDownStyle = "DropDownList"
$comboFilter.Items.AddRange(@("All Updates", "Security Only", "Feature/Bug Fix Only"))
$comboFilter.SelectedIndex = 0
$form.Controls.Add($comboFilter)

$buttonCheck = New-Object System.Windows.Forms.Button
$buttonCheck.Location = New-Object System.Drawing.Point(680, 35)
$buttonCheck.Size = New-Object System.Drawing.Size(120, 30)
$buttonCheck.Text = "Check Updates"
$buttonCheck.BackColor = [System.Drawing.Color]::LightBlue
$buttonCheck.Anchor = "Top,Left"
$form.Controls.Add($buttonCheck)

$buttonDebug = New-Object System.Windows.Forms.Button
$buttonDebug.Location = New-Object System.Drawing.Point(810, 35)
$buttonDebug.Size = New-Object System.Drawing.Size(120, 30)
$buttonDebug.Text = "Debug Feed"
$buttonDebug.BackColor = [System.Drawing.Color]::Orange
$buttonDebug.Anchor = "Top,Left"
$form.Controls.Add($buttonDebug)

$buttonClear = New-Object System.Windows.Forms.Button
$buttonClear.Location = New-Object System.Drawing.Point(680, 70)
$buttonClear.Size = New-Object System.Drawing.Size(120, 30)
$buttonClear.Text = "Clear Results"
$buttonClear.BackColor = [System.Drawing.Color]::LightGray
$buttonClear.Anchor = "Top,Left"
$form.Controls.Add($buttonClear)

$buttonExport = New-Object System.Windows.Forms.Button
$buttonExport.Location = New-Object System.Drawing.Point(810, 70)
$buttonExport.Size = New-Object System.Drawing.Size(120, 30)
$buttonExport.Text = "Export Results"
$buttonExport.BackColor = [System.Drawing.Color]::LightGreen
$buttonExport.Enabled = $false
$buttonExport.Anchor = "Top,Left"
$form.Controls.Add($buttonExport)

$buttonClearHistory = New-Object System.Windows.Forms.Button
$buttonClearHistory.Location = New-Object System.Drawing.Point(940, 70)
$buttonClearHistory.Size = New-Object System.Drawing.Size(120, 30)
$buttonClearHistory.Text = "Clear History"
$buttonClearHistory.BackColor = [System.Drawing.Color]::LightCoral
$buttonClearHistory.Anchor = "Top,Left"
$form.Controls.Add($buttonClearHistory)

$buttonAcknowledge = New-Object System.Windows.Forms.Button
$buttonAcknowledge.Location = New-Object System.Drawing.Point(940, 35)
$buttonAcknowledge.Size = New-Object System.Drawing.Size(120, 30)
$buttonAcknowledge.Text = "Acknowledge (0)"
$buttonAcknowledge.BackColor = [System.Drawing.Color]::LightGoldenrodYellow
$buttonAcknowledge.Enabled = $false
$buttonAcknowledge.Anchor = "Top,Left"
$form.Controls.Add($buttonAcknowledge)

$buttonRefresh = New-Object System.Windows.Forms.Button
$buttonRefresh.Location = New-Object System.Drawing.Point(680, 105)
$buttonRefresh.Size = New-Object System.Drawing.Size(120, 30)
$buttonRefresh.Text = "Test Feed"
$buttonRefresh.BackColor = [System.Drawing.Color]::LightYellow
$buttonRefresh.Anchor = "Top,Left"
$form.Controls.Add($buttonRefresh)

$buttonHelp = New-Object System.Windows.Forms.Button
$buttonHelp.Location = New-Object System.Drawing.Point(810, 105)
$buttonHelp.Size = New-Object System.Drawing.Size(120, 30)
$buttonHelp.Text = "Help / About"
$buttonHelp.BackColor = [System.Drawing.Color]::AliceBlue
$buttonHelp.Anchor = "Top,Left"
$form.Controls.Add($buttonHelp)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(10, 175)
$progressBar.Size = New-Object System.Drawing.Size(1160, 20)
$progressBar.Style = "Continuous"
$progressBar.Visible = $false
$progressBar.Anchor = "Top,Left,Right"
$form.Controls.Add($progressBar)

$labelStatus = New-Object System.Windows.Forms.Label
$labelStatus.Location = New-Object System.Drawing.Point(10, 200)
$labelStatus.Size = New-Object System.Drawing.Size(1160, 20)
$labelStatus.Text = "Ready to check Windows software security updates from PatchMyPC"
$labelStatus.ForeColor = [System.Drawing.Color]::Blue
$labelStatus.Anchor = "Top,Left,Right"
$form.Controls.Add($labelStatus)

$labelResults = New-Object System.Windows.Forms.Label
$labelResults.Location = New-Object System.Drawing.Point(10, 225)
$labelResults.Size = New-Object System.Drawing.Size(400, 20)
$labelResults.Text = "Windows Updates from PatchMyPC:"
$labelResults.Anchor = "Top,Left"
$form.Controls.Add($labelResults)

$labelStats = New-Object System.Windows.Forms.Label
$labelStats.Location = New-Object System.Drawing.Point(420, 225)
$labelStats.Size = New-Object System.Drawing.Size(500, 20)
$labelStats.Text = ""
$labelStats.ForeColor = [System.Drawing.Color]::DarkBlue
$labelStats.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$labelStats.Anchor = "Top,Left"
$form.Controls.Add($labelStats)

$labelSearch = New-Object System.Windows.Forms.Label
$labelSearch.Location = New-Object System.Drawing.Point(940, 225)
$labelSearch.Size = New-Object System.Drawing.Size(50, 20)
$labelSearch.Text = "Filter:"
$labelSearch.Anchor = "Top,Right"
$form.Controls.Add($labelSearch)

$textboxSearch = New-Object System.Windows.Forms.TextBox
$textboxSearch.Location = New-Object System.Drawing.Point(990, 222)
$textboxSearch.Size = New-Object System.Drawing.Size(180, 20)
$textboxSearch.Anchor = "Top,Right"
$form.Controls.Add($textboxSearch)

$dataGridResults = New-Object System.Windows.Forms.DataGridView
$dataGridResults.Location = New-Object System.Drawing.Point(10, 250)
$dataGridResults.Size = New-Object System.Drawing.Size(1160, 455)
$dataGridResults.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$dataGridResults.AllowUserToAddRows = $false
$dataGridResults.AllowUserToDeleteRows = $false
$dataGridResults.ReadOnly = $true
$dataGridResults.AutoSizeColumnsMode = "Fill"
$dataGridResults.SelectionMode = "FullRowSelect"
$dataGridResults.MultiSelect = $true
$dataGridResults.RowHeadersVisible = $false
$dataGridResults.Anchor = "Top,Bottom,Left,Right"
$dataGridResults.AllowUserToOrderColumns = $true
$dataGridResults.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$dataGridResults.EnableHeadersVisualStyles = $false
$dataGridResults.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::LightGray

$colSoftware = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colSoftware.Name = "Software"
$colSoftware.HeaderText = "Software"
$colSoftware.FillWeight = 20
$colSoftware.SortMode = "Automatic"
$dataGridResults.Columns.Add($colSoftware)

$colVersion = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colVersion.Name = "Version"
$colVersion.HeaderText = "Version"
$colVersion.FillWeight = 12
$colVersion.SortMode = "Automatic"
$dataGridResults.Columns.Add($colVersion)

$colType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colType.Name = "UpdateType"
$colType.HeaderText = "Update Type"
$colType.FillWeight = 10
$colType.SortMode = "Automatic"
$dataGridResults.Columns.Add($colType)

$colArchitecture = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colArchitecture.Name = "Architecture"
$colArchitecture.HeaderText = "Architecture"
$colArchitecture.FillWeight = 8
$colArchitecture.SortMode = "Automatic"
$dataGridResults.Columns.Add($colArchitecture)

$colCVEs = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colCVEs.Name = "CVEs"
$colCVEs.HeaderText = "CVE IDs"
$colCVEs.FillWeight = 15
$colCVEs.SortMode = "Automatic"
$dataGridResults.Columns.Add($colCVEs)

$colPublished = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colPublished.Name = "Published"
$colPublished.HeaderText = "Published"
$colPublished.FillWeight = 10
$colPublished.SortMode = "Automatic"
$dataGridResults.Columns.Add($colPublished)

$colStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colStatus.Name = "Status"
$colStatus.HeaderText = "Status"
$colStatus.FillWeight = 8
$colStatus.SortMode = "Automatic"
$dataGridResults.Columns.Add($colStatus)

$form.Controls.Add($dataGridResults)

$labelLastUpdated = New-Object System.Windows.Forms.Label
$labelLastUpdated.Location = New-Object System.Drawing.Point(10, 715)
$labelLastUpdated.Size = New-Object System.Drawing.Size(400, 20)
$labelLastUpdated.Text = "Last checked: Never"
$labelLastUpdated.ForeColor = [System.Drawing.Color]::Gray
$labelLastUpdated.Anchor = "Bottom,Left"
$form.Controls.Add($labelLastUpdated)

$labelHistoryDate = New-Object System.Windows.Forms.Label
$labelHistoryDate.Location = New-Object System.Drawing.Point(10, 735)
$labelHistoryDate.Size = New-Object System.Drawing.Size(400, 20)
$labelHistoryDate.Text = "Previous scan history: Not found"
$labelHistoryDate.ForeColor = [System.Drawing.Color]::Gray
$labelHistoryDate.Anchor = "Bottom,Left"
$form.Controls.Add($labelHistoryDate)

$labelAcknowledged = New-Object System.Windows.Forms.Label
$labelAcknowledged.Location = New-Object System.Drawing.Point(420, 715)
$labelAcknowledged.Size = New-Object System.Drawing.Size(400, 20)
$labelAcknowledged.Text = "Acknowledged items: 0"
$labelAcknowledged.ForeColor = [System.Drawing.Color]::Gray
$labelAcknowledged.Anchor = "Bottom,Left"
$form.Controls.Add($labelAcknowledged)

$labelLegend = New-Object System.Windows.Forms.Label
$labelLegend.Location = New-Object System.Drawing.Point(420, 735)
$labelLegend.Size = New-Object System.Drawing.Size(600, 20)
$labelLegend.Text = "Legend: Red = New | Yellow = Acknowledged | White = Previously Seen"
$labelLegend.ForeColor = [System.Drawing.Color]::Gray
$labelLegend.Anchor = "Bottom,Left"
$form.Controls.Add($labelLegend)

# ===== EVENT HANDLERS =====

$buttonLoadFile.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
    $openFileDialog.Title = "Select Software List File"
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    
    if ($openFileDialog.ShowDialog() -eq "OK") {
        try {
            $fileContent = Get-Content -Path $openFileDialog.FileName -Raw
            $textboxSoftware.Text = $fileContent
            $labelStatus.Text = "Loaded software list from: $($openFileDialog.FileName)"
            $labelStatus.ForeColor = [System.Drawing.Color]::Green
        } catch {
            $labelStatus.Text = "Error loading file: $($_.Exception.Message)"
            $labelStatus.ForeColor = [System.Drawing.Color]::Red
            [System.Windows.Forms.MessageBox]::Show("Could not load the file.`n`nError: $($_.Exception.Message)", "File Load Error", "OK", "Error")
        }
        $form.Refresh()
    }
})

$buttonCheck.Add_Click({
    $dataGridResults.Rows.Clear()
    $buttonExport.Enabled = $false
    $buttonAcknowledge.Enabled = $false
    $labelStatus.Text = "Starting update check..."
    $labelStats.Text = ""
    $form.Refresh()

    $acknowledgedItems = @{}
    $ackData = Load-JsonSafely -Path $acknowledgedFilePath
    if ($null -ne $ackData) {
        foreach ($item in $ackData) {
            $key = "$($item.Software)-$($item.Version)-$($item.Architecture)"
            $acknowledgedItems[$key] = $item.AcknowledgedDate
        }
    }
    $labelAcknowledged.Text = "Acknowledged items: $($acknowledgedItems.Count)"

    $historyExists = $false
    $previousResults = Load-JsonSafely -Path $stateFilePath
    if ($null -ne $previousResults) {
        $historyDate = (Get-Item $stateFilePath).LastWriteTime
        $labelHistoryDate.Text = "Previous scan history from: $($historyDate.ToString('yyyy-MM-dd HH:mm:ss'))"
        $historyExists = $true
    } else {
        $labelHistoryDate.Text = "Previous scan history: Not found"
    }

    $previousKeys = @{}
    if ($previousResults) {
        foreach ($item in $previousResults) {
            $key = "$($item.Software)-$($item.Version)-$($item.Architecture)"
            if (-not $previousKeys.ContainsKey($key)) {
                $previousKeys.Add($key, $true)
            }
        }
    }
    
    $softwareList = $textboxSoftware.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $daysBack = [int]$numericDaysBack.Value
    $filterType = $comboFilter.SelectedItem.ToString()
    
    if ($softwareList.Count -eq 0) {
        $labelStatus.Text = "Error: No valid software names provided"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
        $form.Refresh()
        return
    }
    
    $results = Get-PatchMyPCUpdates -SoftwareList $softwareList -DaysBack $daysBack -FilterType $filterType
    
    if ($results.Count -eq 0) {
        $labelStatus.Text = "No updates found matching criteria."
        $labelStatus.ForeColor = [System.Drawing.Color]::Orange
        $labelStats.Text = ""
    } else {
        $newCount = 0
        $acknowledgedCount = 0
        
        foreach ($result in $results) {
            try {
                $currentKey = "$($result.Software)-$($result.Version)-$($result.Architecture)"
                
                $status = "Previously Seen"
                $rowColor = [System.Drawing.Color]::White
                
                if ($acknowledgedItems.ContainsKey($currentKey)) {
                    $status = "Acknowledged"
                    $rowColor = [System.Drawing.Color]::LightYellow
                    $acknowledgedCount++
                } elseif ($historyExists -and (-not $previousKeys.ContainsKey($currentKey))) {
                    $status = "NEW"
                    $rowColor = [System.Drawing.Color]::LightCoral
                    $newCount++
                }
                
                $rowIndex = $dataGridResults.Rows.Add($result.Software, $result.Version, $result.UpdateType, $result.Architecture, $result.CVEs, $result.Published, $status)
                $dataGridResults.Rows[$rowIndex].DefaultCellStyle.BackColor = $rowColor
            } catch {
                $labelStatus.Text = "Error adding row: $($_.Exception.Message)"
                $labelStatus.ForeColor = [System.Drawing.Color]::Red
            }
        }
        
        Save-JsonSafely -Data $results -Path $stateFilePath | Out-Null
        
        $securityCount = 0
        $totalCVEs = 0
        $uniqueSoftware = @{}
        
        foreach ($result in $results) {
            if ($result.UpdateType -eq "Security") { $securityCount++ }
            if (-not [string]::IsNullOrWhiteSpace($result.CVEs)) { $totalCVEs++ }
            if (-not $uniqueSoftware.ContainsKey($result.Software)) { $uniqueSoftware[$result.Software] = $true }
        }
        
        $labelStats.Text = "Summary: $securityCount Security Updates | $totalCVEs with CVEs | $($uniqueSoftware.Count) Software Products"
        
        $statusMsg = "Successfully loaded $($results.Count) updates"
        if ($newCount -gt 0) { $statusMsg += " ($newCount NEW)" }
        if ($acknowledgedCount -gt 0) { $statusMsg += " ($acknowledgedCount acknowledged)" }
        
        $labelStatus.Text = $statusMsg
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
        $buttonExport.Enabled = $true
    }
    
    $form.Refresh()
})

$buttonClear.Add_Click({
    $dataGridResults.Rows.Clear()
    Clear-PageCache
    $labelStatus.Text = "Results and cache cleared"
    $labelStatus.ForeColor = [System.Drawing.Color]::Blue
    $labelStats.Text = ""
    $buttonExport.Enabled = $false
    $buttonAcknowledge.Enabled = $false
    $form.Refresh()
})

$buttonAcknowledge.Add_Click({
    if ($dataGridResults.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please select one or more items to acknowledge.", "No Selection", "OK", "Information")
        return
    }
    
    $acknowledgedItems = @()
    $ackData = Load-JsonSafely -Path $acknowledgedFilePath
    if ($null -ne $ackData) { $acknowledgedItems = @($ackData) }
    
    $existingKeys = @{}
    foreach ($item in $acknowledgedItems) {
        $key = "$($item.Software)-$($item.Version)-$($item.Architecture)"
        $existingKeys[$key] = $true
    }
    
    $newlyAcknowledged = 0
    $alreadyAcknowledged = 0
    
    foreach ($selectedRow in $dataGridResults.SelectedRows) {
        $software = $selectedRow.Cells["Software"].Value
        $version = $selectedRow.Cells["Version"].Value
        $architecture = $selectedRow.Cells["Architecture"].Value
        $key = "$software-$version-$architecture"
        
        if ($existingKeys.ContainsKey($key)) {
            $alreadyAcknowledged++
            continue
        }
        
        $acknowledgedItems += [PSCustomObject]@{
            Software = $software
            Version = $version
            Architecture = $architecture
            AcknowledgedDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        }
        
        $existingKeys[$key] = $true
        $selectedRow.Cells["Status"].Value = "Acknowledged"
        $selectedRow.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightYellow
        $newlyAcknowledged++
    }
    
    if (Save-JsonSafely -Data $acknowledgedItems -Path $acknowledgedFilePath) {
        $statusMsg = ""
        if ($newlyAcknowledged -gt 0) { $statusMsg = "Acknowledged $newlyAcknowledged item(s)" }
        if ($alreadyAcknowledged -gt 0) {
            if ($statusMsg) { $statusMsg += "; " }
            $statusMsg += "$alreadyAcknowledged already acknowledged"
        }
        $labelStatus.Text = $statusMsg
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
        $labelAcknowledged.Text = "Acknowledged items: $($acknowledgedItems.Count)"
    } else {
        $labelStatus.Text = "Error acknowledging items"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
    }
    $form.Refresh()
})

$dataGridResults.Add_SelectionChanged({
    $selectedCount = $dataGridResults.SelectedRows.Count
    if ($selectedCount -gt 0) {
        $buttonAcknowledge.Enabled = $true
        $buttonAcknowledge.Text = "Acknowledge ($selectedCount)"
    } else {
        $buttonAcknowledge.Enabled = $false
        $buttonAcknowledge.Text = "Acknowledge (0)"
    }
})

$buttonClearHistory.Add_Click({
    $result = [System.Windows.Forms.MessageBox]::Show("This will clear both scan history and acknowledged items. Are you sure?", "Confirm Clear All", "YesNo", "Warning")
    
    if ($result -eq "Yes") {
        $clearedItems = @()
        
        if (Test-Path $stateFilePath) {
            try {
                Remove-Item -Path $stateFilePath -ErrorAction Stop
                $clearedItems += "scan history"
            } catch {
                $labelStatus.Text = "Error clearing scan history: $($_.Exception.Message)"
                $labelStatus.ForeColor = [System.Drawing.Color]::Red
                $form.Refresh()
                return
            }
        }
        
        if (Test-Path $acknowledgedFilePath) {
            try {
                Remove-Item -Path $acknowledgedFilePath -ErrorAction Stop
                $clearedItems += "acknowledged items"
            } catch {
                $labelStatus.Text = "Error clearing acknowledged items: $($_.Exception.Message)"
                $labelStatus.ForeColor = [System.Drawing.Color]::Red
                $form.Refresh()
                return
            }
        }
        
        if ($clearedItems.Count -gt 0) {
            $labelStatus.Text = "Cleared: $($clearedItems -join ' and ')"
            $labelStatus.ForeColor = [System.Drawing.Color]::Blue
            $labelHistoryDate.Text = "Previous scan history: Not found"
            $labelAcknowledged.Text = "Acknowledged items: 0"
        } else {
            $labelStatus.Text = "No history or acknowledged items to clear."
            $labelStatus.ForeColor = [System.Drawing.Color]::Blue
        }
    }
    $form.Refresh()
})

$buttonExport.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv"
    $saveFileDialog.Title = "Save Update Report"
    $saveFileDialog.FileName = "PatchMyPC_Updates_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $saveFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    
    if ($saveFileDialog.ShowDialog() -eq "OK") {
        try {
            $exportData = @()
            foreach ($row in $dataGridResults.Rows) {
                if ($row.Cells["Software"].Value) {
                    $exportData += [PSCustomObject]@{
                        Software = $row.Cells["Software"].Value
                        Version = $row.Cells["Version"].Value
                        UpdateType = $row.Cells["UpdateType"].Value
                        Architecture = $row.Cells["Architecture"].Value
                        CVEs = $row.Cells["CVEs"].Value
                        Published = $row.Cells["Published"].Value
                        Status = $row.Cells["Status"].Value
                    }
                }
            }
            
            $exportData | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation
            $labelStatus.Text = "Results exported to $($saveFileDialog.FileName)"
            $labelStatus.ForeColor = [System.Drawing.Color]::Green
        } catch {
            $labelStatus.Text = "Error exporting: $($_.Exception.Message)"
            $labelStatus.ForeColor = [System.Drawing.Color]::Red
        }
        $form.Refresh()
    }
})

$buttonDebug.Add_Click({
    $labelStatus.Text = "Debug mode: Checking connectivity..."
    $form.Refresh()
    try {
        $testRequest = Invoke-WebRequest -Uri "https://patchmypc.com/" -TimeoutSec 10 -UseBasicParsing
        $labelStatus.Text = "Debug: Successfully connected (Status: $($testRequest.StatusCode))"
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
    } catch {
        $labelStatus.Text = "Debug ERROR: $($_.Exception.Message)"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
    }
    $form.Refresh()
})

$buttonRefresh.Add_Click({
    try {
        $headers = @{'Accept-Language' = 'en-US,en;q=0.9'; 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        $testRequest = Invoke-WebRequest -Uri "https://patchmypc.com/category/catalog-updates/" -TimeoutSec 10 -Headers $headers -UseBasicParsing
        $catalogUrls = [regex]::Matches($testRequest.Content, 'href="(https://patchmypc\.com/catalog-release/\d{4}/\d{2}-\d{2}-\d{2}/)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -First 1
        $labelStatus.Text = "Test Feed: Latest catalog found: ${catalogUrls}"
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
    } catch {
        $labelStatus.Text = "Test Feed ERROR: $($_.Exception.Message)"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
    }
    $form.Refresh()
})

$buttonHelp.Add_Click({
    $helpForm = New-Object System.Windows.Forms.Form
    $helpForm.Text = "Help / About - PatchMyPC Update Checker"
    $helpForm.Size = New-Object System.Drawing.Size(650, 550)
    $helpForm.StartPosition = "CenterParent"
    $helpForm.FormBorderStyle = "FixedDialog"
    $helpForm.MaximizeBox = $false
    $helpForm.MinimizeBox = $false

    $helpTextBox = New-Object System.Windows.Forms.TextBox
    $helpTextBox.Multiline = $true
    $helpTextBox.ReadOnly = $true
    $helpTextBox.Dock = "Fill"
    $helpTextBox.ScrollBars = "Vertical"
    $helpTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)

    $helpText = "PatchMyPC Update Checker - Help`n`n"
    $helpText += "VERSION: $script:AppVersion`n`n"
    $helpText += "FEATURES`n"
    $helpText += "- Check Windows software for security updates`n"
    $helpText += "- Track new updates (RED) vs acknowledged (YELLOW)`n"
    $helpText += "- Filter by Security/Feature updates`n"
    $helpText += "- Sortable columns, search/filter results`n"
    $helpText += "- Export to CSV`n`n"
    $helpText += "HOW TO USE`n"
    $helpText += "1. Enter software names (one per line) or load from file`n"
    $helpText += "2. Set days back to check (1-365)`n"
    $helpText += "3. Click 'Check Updates'`n"
    $helpText += "4. NEW items appear in RED`n"
    $helpText += "5. Select items and click 'Acknowledge' to mark as handled (YELLOW)`n"
    $helpText += "6. Use Filter box to search results`n"
    $helpText += "7. Double-click any cell to copy value`n`n"
    $helpText += "IMPROVEMENTS IN v2.1.0`n"
    $helpText += "- More accurate CVE detection`n"
    $helpText += "- Better language filtering`n"
    $helpText += "- Page caching (5 min)`n"
    $helpText += "- Retry logic for network errors`n"
    $helpText += "- Statistics summary`n"
    $helpText += "- Sortable columns`n"
    $helpText += "- Real-time search`n`n"
    $helpText += "ARCHITECTURE TYPES`n"
    $helpText += "x64 = 64-bit`n"
    $helpText += "EXE-x64 = Executable installer`n"
    $helpText += "MSI-x64 = Windows Installer package`n"
    $helpText += "User-x64 = Per-user install (no admin)`n"
    $helpText += "System = System-wide (admin required)`n`n"
    $helpText += "Data Source: PatchMyPC (https://patchmypc.com)"

    $helpTextBox.Text = $helpText.Replace("`n", [Environment]::NewLine)
    $helpForm.Controls.Add($helpTextBox)
    $helpForm.ShowDialog()
})

$textboxSearch.Add_TextChanged({
    $searchText = $textboxSearch.Text
    if ([string]::IsNullOrWhiteSpace($searchText)) {
        foreach ($row in $dataGridResults.Rows) { $row.Visible = $true }
    } else {
        foreach ($row in $dataGridResults.Rows) {
            $visible = $false
            foreach ($cell in $row.Cells) {
                if ($cell.Value -and $cell.Value.ToString() -like "*$searchText*") {
                    $visible = $true
                    break
                }
            }
            $row.Visible = $visible
        }
    }
})

$dataGridResults.Add_CellDoubleClick({
    param($sender, $e)
    if ($e.RowIndex -ge 0 -and $e.ColumnIndex -ge 0) {
        $cellValue = $dataGridResults.Rows[$e.RowIndex].Cells[$e.ColumnIndex].Value
        if ($cellValue) {
            [System.Windows.Forms.Clipboard]::SetText($cellValue.ToString())
            $labelStatus.Text = "Copied to clipboard: $cellValue"
            $labelStatus.ForeColor = [System.Drawing.Color]::Green
        }
    }
})

$form.ShowDialog()
