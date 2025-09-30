# Windows Security Update Checker GUI using PatchMyPC Feed
# Enhanced version with file loading capability and improved accuracy

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO

# Centralized file paths
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

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Security Update Checker (PatchMyPC)"
$form.Size = New-Object System.Drawing.Size(1200, 800)
$form.StartPosition = "CenterScreen"
$form.MaximizeBox = $true
$form.MinimumSize = New-Object System.Drawing.Size(1000, 600)

# Software list input
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

# Load from file button
$buttonLoadFile = New-Object System.Windows.Forms.Button
$buttonLoadFile.Location = New-Object System.Drawing.Point(10, 140)
$buttonLoadFile.Size = New-Object System.Drawing.Size(120, 25)
$buttonLoadFile.Text = "Load from File..."
$buttonLoadFile.BackColor = [System.Drawing.Color]::LightSkyBlue
$form.Controls.Add($buttonLoadFile)

# Date selection section
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

# Filter section
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

# Create all buttons
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

# Progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(10, 175)
$progressBar.Size = New-Object System.Drawing.Size(1160, 20)
$progressBar.Style = "Continuous"
$progressBar.Visible = $false
$progressBar.Anchor = "Top,Left,Right"
$form.Controls.Add($progressBar)

# Status label
$labelStatus = New-Object System.Windows.Forms.Label
$labelStatus.Location = New-Object System.Drawing.Point(10, 200)
$labelStatus.Size = New-Object System.Drawing.Size(1160, 20)
$labelStatus.Text = "Ready to check Windows software security updates from PatchMyPC"
$labelStatus.ForeColor = [System.Drawing.Color]::Blue
$labelStatus.Anchor = "Top,Left,Right"
$form.Controls.Add($labelStatus)

# Results display with DataGridView
$labelResults = New-Object System.Windows.Forms.Label
$labelResults.Location = New-Object System.Drawing.Point(10, 225)
$labelResults.Size = New-Object System.Drawing.Size(400, 20)
$labelResults.Text = "Windows Updates from PatchMyPC:"
$labelResults.Anchor = "Top,Left"
$form.Controls.Add($labelResults)

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

# Add columns
$colSoftware = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colSoftware.Name = "Software"
$colSoftware.HeaderText = "Software"
$colSoftware.FillWeight = 20
$dataGridResults.Columns.Add($colSoftware)

$colVersion = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colVersion.Name = "Version"
$colVersion.HeaderText = "Version"
$colVersion.FillWeight = 12
$dataGridResults.Columns.Add($colVersion)

$colType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colType.Name = "UpdateType"
$colType.HeaderText = "Update Type"
$colType.FillWeight = 10
$dataGridResults.Columns.Add($colType)

$colArchitecture = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colArchitecture.Name = "Architecture"
$colArchitecture.HeaderText = "Architecture"
$colArchitecture.FillWeight = 8
$dataGridResults.Columns.Add($colArchitecture)

$colCVEs = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colCVEs.Name = "CVEs"
$colCVEs.HeaderText = "CVE IDs"
$colCVEs.FillWeight = 15
$dataGridResults.Columns.Add($colCVEs)

$colPublished = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colPublished.Name = "Published"
$colPublished.HeaderText = "Published"
$colPublished.FillWeight = 10
$dataGridResults.Columns.Add($colPublished)

$colStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colStatus.Name = "Status"
$colStatus.HeaderText = "Status"
$colStatus.FillWeight = 8
$dataGridResults.Columns.Add($colStatus)

$form.Controls.Add($dataGridResults)

# Last updated label
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

# Legend for status colors
$labelLegend = New-Object System.Windows.Forms.Label
$labelLegend.Location = New-Object System.Drawing.Point(420, 735)
$labelLegend.Size = New-Object System.Drawing.Size(600, 20)
$labelLegend.Text = "Legend: Red = New | Yellow = Acknowledged | White = Previously Seen"
$labelLegend.ForeColor = [System.Drawing.Color]::Gray
$labelLegend.Anchor = "Bottom,Left"
$form.Controls.Add($labelLegend)

# Function to parse PatchMyPC catalog pages
function Get-PatchMyPCUpdates {
    param(
        [string[]]$SoftwareList,
        [int]$DaysBack,
        [string]$FilterType = "All Updates"
    )
    
    $results = @()
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    $processedUpdates = @{}
    
    try {
        $labelStatus.Text = "Downloading recent PatchMyPC catalog pages..."
        $progressBar.Visible = $true
        $progressBar.Value = 0
        $form.Refresh()
        
        $headers = @{
            'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            'Accept-Language' = 'en-US,en;q=0.9'
        }
        
        $mainPage = Invoke-WebRequest -Uri "https://patchmypc.com/category/catalog-updates/" -TimeoutSec 30 -Headers $headers -UseBasicParsing -ErrorAction Stop
        
        $catalogUrls = [regex]::Matches($mainPage.Content, 'href="(https://patchmypc\.com/catalog-release/\d{4}/\d{2}-\d{2}-\d{2}/)"') | 
                       ForEach-Object { $_.Groups[1].Value } | 
                       Select-Object -Unique |
                       Select-Object -First 15
        
        $processedPages = 0
        $totalPages = $catalogUrls.Count
        $progressBar.Maximum = $totalPages
        
        foreach ($catalogUrl in $catalogUrls) {
            $processedPages++
            $progressBar.Value = $processedPages
            $labelStatus.Text = "Checking catalog page $processedPages of $totalPages..."
            $form.Refresh()
            
            try {
                if ($catalogUrl -match '/(\d{4})/(\d{2})-(\d{2})-(\d{2})/') {
                    $year = [int]$matches[1]
                    $month = [int]$matches[2]
                    $day = [int]$matches[3]
                    $catalogDate = Get-Date -Year $year -Month $month -Day $day
                    
                    if ($catalogDate -lt $cutoffDate) {
                        continue
                    }
                }
                
                $catalogPage = Invoke-WebRequest -Uri $catalogUrl -TimeoutSec 30 -Headers $headers -UseBasicParsing -ErrorAction Stop
                $pageContent = $catalogPage.Content
                
                foreach ($software in $SoftwareList) {
                    if ([string]::IsNullOrWhiteSpace($software)) { 
                        continue 
                    }
                    
                    $searchTerms = @($software)
                    if ($software -eq "Microsoft Visual Studio Code") {
                        $searchTerms += @("Visual Studio Code")
                    } elseif ($software -eq "Adobe Acrobat Reader") {
                        $searchTerms += @("Adobe Acrobat Reader DC", "Adobe Acrobat DC", "Adobe Reader", "Adobe Acrobat", "Acrobat Reader", "Acrobat DC", "Adobe Acrobat Classic")
                    } elseif ($software -eq "Git for Windows") {
                        $searchTerms += @("Git")
                    } elseif ($software -eq "7-Zip") {
                        $searchTerms += @("7Zip", "7-zip")
                    }
                    
                    foreach ($term in $searchTerms) {
                        $pattern = [regex]::Escape($term) + '\s+([\d\.]+)\s*\(([^\)]+)\)'
                        $matches = [regex]::Matches($pageContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                        
                        foreach ($match in $matches) {
                            $version = $match.Groups[1].Value
                            $architecture = if ($match.Groups.Count -gt 2) { $match.Groups[2].Value } else { "Unknown" }
                            
                            # Only process x64 architectures and filter out non-English language codes
                            if ($architecture -notmatch 'x64') {
                                continue
                            }
                            
                            # Skip non-English language versions
                            # Filter out all language-specific versions including English variants
                            # Only keep entries without language codes or generic x64
                            $languageCodes = @(
                                # Non-English languages
                                'de-DE', 'fr-FR', 'es-ES', 'es-AR', 'es-MX', 'es-CL', 'es-CO', 
                                'it-IT', 'pt-PT', 'pt-BR', 'nl-NL', 'da-DK', 'sv-SE', 'nb-NO', 
                                'fi-FI', 'pl-PL', 'cs-CZ', 'hu-HU', 'ru-RU', 'ja-JP', 'ko-KR', 
                                'zh-CN', 'zh-TW', 'ar-SA', 'he-IL', 'tr-TR', 'el-GR', 'uk-UA',
                                'de', 'fr', 'es', 'it', 'pt', 'nl', 'da', 'sv', 'nb',
                                'fi', 'pl', 'cs', 'hu', 'ru', 'ja', 'ko', 'zh', 'ar',
                                'he', 'tr', 'el', 'uk', 'MUI', 'ML',
                                # English variants (if you want to filter these out too)
                                'en-US', 'en-GB', 'en-CA', 'en-AU', 'en-NZ', 'en-IE'
                            )
                            
                            $hasLanguageCode = $false
                            foreach ($lang in $languageCodes) {
                                # Match language codes as whole words at word boundaries or end of string
                                if ($architecture -match "(\s|^)$([regex]::Escape($lang))(\s|$)") {
                                    $hasLanguageCode = $true
                                    break
                                }
                            }
                            
                            if ($hasLanguageCode) {
                                continue
                            }
                            
                            $uniqueKey = "$($software)-$($version)-$($architecture)"
                            if ($processedUpdates.ContainsKey($uniqueKey)) {
                                continue
                            }
                            
                            $cveIds = @()
                            # Expand context window significantly to capture CVE-IDs section
                            $contextStartIndex = [Math]::Max(0, $match.Index - 500)
                            $contextLength = [Math]::Min($pageContent.Length - $contextStartIndex, 2000) 
                            $searchContext = $pageContent.Substring($contextStartIndex, $contextLength)
                            
                            # Look for CVE-IDs: section first (most reliable)
                            if ($searchContext -match 'CVE-IDs:\s*([^<\n]+)') {
                                $cveSection = $matches[1]
                                $cvePattern = 'CVE-\d{4}-\d{4,7}'
                                $cveMatches = [regex]::Matches($cveSection, $cvePattern)
                                if ($cveMatches.Count -gt 0) {
                                    $cveIds = $cveMatches | ForEach-Object { $_.Value } | Select-Object -Unique
                                }
                            }
                            
                            # Fallback: search for any CVE references in context
                            if ($cveIds.Count -eq 0) {
                                $cvePattern = 'CVE-\d{4}-\d{4,7}'
                                $cveMatches = [regex]::Matches($searchContext, $cvePattern)
                                if ($cveMatches.Count -gt 0) {
                                    $cveIds = $cveMatches | ForEach-Object { $_.Value } | Select-Object -Unique
                                }
                            }
                            
                            # Enhanced security detection
                            $updateType = "Feature/Bug Fix"
                            $securityKeywords = @(
                                'Security (Update|Release|Fix|Patch)',
                                'Vulnerability',
                                'Critical Update',
                                'Security Advisory'
                            )
                            
                            $isSecurityUpdate = $false
                            if ($cveMatches.Count -gt 0) {
                                $isSecurityUpdate = $true
                            } else {
                                foreach ($keyword in $securityKeywords) {
                                    if ($searchContext -match $keyword) {
                                        $isSecurityUpdate = $true
                                        break
                                    }
                                }
                            }
                            
                            if ($isSecurityUpdate) {
                                $updateType = "Security"
                            }
                            
                            if ($FilterType -eq "Security Only" -and $updateType -ne "Security") {
                                continue
                            }
                            if ($FilterType -eq "Feature/Bug Fix Only" -and $updateType -ne "Feature/Bug Fix") {
                                continue
                            }
                            
                            $processedUpdates.Add($uniqueKey, $true)
                            $results += [PSCustomObject]@{
                                Software = $software
                                Version = $version
                                UpdateType = $updateType
                                Architecture = $architecture
                                CVEs = ($cveIds -join ", ")
                                Published = $catalogDate.ToString("yyyy-MM-dd")
                            }
                        }
                    }
                }
            } catch {
                $labelStatus.Text = "Error checking page: $($_.Exception.Message)"
                $labelStatus.ForeColor = [System.Drawing.Color]::Red
                $form.Refresh()
                Start-Sleep -Milliseconds 500
            }
        }
        
        $labelStatus.Text = "Completed checking $processedPages pages, found $($results.Count) updates"
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
        $labelLastUpdated.Text = "Last checked: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    } catch {
        $labelStatus.Text = "Error downloading catalog: $($_.Exception.Message)"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
    } finally {
        $progressBar.Visible = $false
        $form.Refresh()
    }
        
    return $results
}

# Load from file button handler
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
            [System.Windows.Forms.MessageBox]::Show("Could not load the file. Please ensure it's a valid text file.`n`nError: $($_.Exception.Message)", "File Load Error", "OK", "Error")
        }
        $form.Refresh()
    }
})

# Button event handlers
$buttonCheck.Add_Click({
    $dataGridResults.Rows.Clear()
    $buttonExport.Enabled = $false
    $buttonAcknowledge.Enabled = $false
    $labelStatus.Text = "Starting update check..."
    $form.Refresh()

    # Load acknowledged items
    $acknowledgedItems = @{}
    if (Test-Path $acknowledgedFilePath) {
        try {
            $ackData = Get-Content -Path $acknowledgedFilePath -Raw | ConvertFrom-Json
            foreach ($item in $ackData) {
                $key = "$($item.Software)-$($item.Version)-$($item.Architecture)"
                $acknowledgedItems[$key] = $item.AcknowledgedDate
            }
        } catch {
            $labelStatus.Text = "Warning: Could not read acknowledged items. $($_.Exception.Message)"
        }
    }
    $labelAcknowledged.Text = "Acknowledged items: $($acknowledgedItems.Count)"

    $historyExists = $false
    $previousResults = @()
    if (Test-Path $stateFilePath) {
        try {
            $previousResults = Get-Content -Path $stateFilePath -Raw | ConvertFrom-Json
            $historyDate = (Get-Item $stateFilePath).LastWriteTime
            $labelHistoryDate.Text = "Previous scan history from: $($historyDate.ToString('yyyy-MM-dd HH:mm:ss'))"
            $historyExists = $true
        } catch {
            $labelStatus.Text = "Warning: Could not read history file. $($_.Exception.Message)"
            $labelHistoryDate.Text = "Previous scan history: Error reading file"
        }
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
    } else {
        $newCount = 0
        $acknowledgedCount = 0
        
        foreach ($result in $results) {
            try {
                $currentKey = "$($result.Software)-$($result.Version)-$($result.Architecture)"
                
                # Determine status
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
                
                $rowIndex = $dataGridResults.Rows.Add(
                    $result.Software,
                    $result.Version,
                    $result.UpdateType,
                    $result.Architecture,
                    $result.CVEs,
                    $result.Published,
                    $status
                )

                $dataGridResults.Rows[$rowIndex].DefaultCellStyle.BackColor = $rowColor

            } catch {
                $labelStatus.Text = "Error adding row to grid: $($_.Exception.Message)"
                $labelStatus.ForeColor = [System.Drawing.Color]::Red
            }
        }
        
        try {
            $results | ConvertTo-Json -Depth 3 | Out-File -FilePath $stateFilePath
        } catch {
            $labelStatus.Text = "Warning: Could not save scan history file. $($_.Exception.Message)"
        }
        
        $statusMsg = "Successfully loaded $($results.Count) updates"
        if ($newCount -gt 0) {
            $statusMsg += " ($newCount NEW)"
        }
        if ($acknowledgedCount -gt 0) {
            $statusMsg += " ($acknowledgedCount acknowledged)"
        }
        
        $labelStatus.Text = $statusMsg
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
        $buttonExport.Enabled = $true
    }
    
    $form.Refresh()
})

$buttonClear.Add_Click({
    $dataGridResults.Rows.Clear()
    $labelStatus.Text = "Results cleared"
    $labelStatus.ForeColor = [System.Drawing.Color]::Blue
    $buttonExport.Enabled = $false
    $buttonAcknowledge.Enabled = $false
    $form.Refresh()
})

$buttonAcknowledge.Add_Click({
    if ($dataGridResults.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please select one or more items to acknowledge.", "No Selection", "OK", "Information")
        return
    }
    
    # Load existing acknowledged items
    $acknowledgedItems = @()
    if (Test-Path $acknowledgedFilePath) {
        try {
            $acknowledgedItems = Get-Content -Path $acknowledgedFilePath -Raw | ConvertFrom-Json
            if ($acknowledgedItems -isnot [array]) {
                $acknowledgedItems = @($acknowledgedItems)
            }
        } catch {
            $acknowledgedItems = @()
        }
    }
    
    # Build existing keys for quick lookup
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
        
        # Check if already acknowledged
        if ($existingKeys.ContainsKey($key)) {
            $alreadyAcknowledged++
            continue
        }
        
        # Add to acknowledged list
        $acknowledgedItems += [PSCustomObject]@{
            Software = $software
            Version = $version
            Architecture = $architecture
            AcknowledgedDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        }
        
        $existingKeys[$key] = $true
        
        # Update the row
        $selectedRow.Cells["Status"].Value = "Acknowledged"
        $selectedRow.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightYellow
        
        $newlyAcknowledged++
    }
    
    try {
        $acknowledgedItems | ConvertTo-Json -Depth 3 | Out-File -FilePath $acknowledgedFilePath
        
        $statusMsg = ""
        if ($newlyAcknowledged -gt 0) {
            $statusMsg = "Acknowledged $newlyAcknowledged item(s)"
        }
        if ($alreadyAcknowledged -gt 0) {
            if ($statusMsg) { $statusMsg += "; " }
            $statusMsg += "$alreadyAcknowledged already acknowledged"
        }
        
        $labelStatus.Text = $statusMsg
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
        $labelAcknowledged.Text = "Acknowledged items: $($acknowledgedItems.Count)"
    } catch {
        $labelStatus.Text = "Error acknowledging items: $($_.Exception.Message)"
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
    $result = [System.Windows.Forms.MessageBox]::Show(
        "This will clear both scan history and acknowledged items. Are you sure?",
        "Confirm Clear All",
        "YesNo",
        "Warning"
    )
    
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
    $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv|Text Files (*.txt)|*.txt"
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
                    }
                }
            }
            
            $exportData | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation
            $labelStatus.Text = "Results exported to $($saveFileDialog.FileName)"
            $labelStatus.ForeColor = [System.Drawing.Color]::Green
        } catch {
            $labelStatus.Text = "Error exporting results: $($_.Exception.Message)"
            $labelStatus.ForeColor = [System.Drawing.Color]::Red
            [System.Windows.Forms.MessageBox]::Show("Could not export the results.`n`nError: $($_.Exception.Message)", "Export Error", "OK", "Error")
        }
        $form.Refresh()
    }
})

$buttonDebug.Add_Click({
    $labelStatus.Text = "Debug mode: Checking connectivity to PatchMyPC..."
    $form.Refresh()
    
    try {
        $testRequest = Invoke-WebRequest -Uri "https://patchmypc.com/" -TimeoutSec 10 -UseBasicParsing
        $labelStatus.Text = "Debug: Successfully connected to PatchMyPC (Status: $($testRequest.StatusCode))"
        $labelStatus.ForeColor = [System.Drawing.Color]::Green
    } catch {
        $labelStatus.Text = "Debug ERROR: $($_.Exception.Message)"
        $labelStatus.ForeColor = [System.Drawing.Color]::Red
    }
    $form.Refresh()
})

$buttonRefresh.Add_Click({
    try {
        $headers = @{
            'Accept-Language' = 'en-US,en;q=0.9'
            'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        $testRequest = Invoke-WebRequest -Uri "https://patchmypc.com/category/catalog-updates/" -TimeoutSec 10 -Headers $headers -UseBasicParsing
        $catalogUrls = [regex]::Matches($testRequest.Content, 'href="(https://patchmypc\.com/catalog-release/\d{4}/\d{2}-\d{2}-\d{2}/)"') | 
                       ForEach-Object { $_.Groups[1].Value } | 
                       Select-Object -First 1
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
    $helpTextBox.Padding = New-Object System.Windows.Forms.Padding(10)

    $helpText = "## PatchMyPC Update Checker - Help`n`n"
    $helpText += "VERSION: 2.0 Enhanced`n`n"
    $helpText += "---`n`n"
    $helpText += "## Features`n`n"
    $helpText += "- Check Windows software for security updates from PatchMyPC catalog`n"
    $helpText += "- Filter updates by type (All/Security/Feature)`n"
    $helpText += "- Track new updates with visual highlighting (RED = New)`n"
    $helpText += "- Acknowledge items you've handled (YELLOW = Acknowledged)`n"
    $helpText += "- Export results to CSV format`n"
    $helpText += "- Load software lists from text files`n`n"
    $helpText += "---`n`n"
    $helpText += "## How to Use`n`n"
    $helpText += "1. Enter software names (one per line) or load from a file`n"
    $helpText += "2. Set the number of days back to check`n"
    $helpText += "3. Choose a filter type (All/Security Only/Feature Only)`n"
    $helpText += "4. Click 'Check Updates' to scan PatchMyPC catalog`n"
    $helpText += "5. NEW updates will be highlighted in RED`n"
    $helpText += "6. Select one or MORE items (Ctrl+Click or Shift+Click) and click 'Acknowledge' to mark as handled (turns YELLOW)`n"
    $helpText += "7. Export results using the 'Export Results' button`n`n"
    $helpText += "---`n`n"
    $helpText += "## Understanding Architecture Types`n`n"
    $helpText += "The architecture types describe the software's design, installer packaging, and installation method.`n`n"
    $helpText += "Core Concept: x64 Architecture`n`n"
    $helpText += "x64 refers to 64-bit architecture that powers modern computers. Compared to 32-bit (x86), x64 processors handle more data simultaneously and access significantly more RAM.`n`n"
    $helpText += "Installer Packages: EXE vs MSI`n`n"
    $helpText += "EXE-x64: A 64-bit executable file (.exe). Flexible installers common for consumer applications with custom interfaces.`n`n"
    $helpText += "MSI-x64: A 64-bit Microsoft Installer file (.msi). Uses Windows Installer service for reliable, predictable installations. Ideal for corporate/automated deployments.`n`n"
    $helpText += "Installation Context: User vs System`n`n"
    $helpText += "User-x64: Installs ONLY for the current user (e.g., AppData folder). Does NOT require administrator privileges.`n`n"
    $helpText += "System (x64/EXE-x64/MSI-x64): System-wide installation for all users (e.g., Program Files). Requires administrator privileges.`n`n"
    $helpText += "---`n`n"
    $helpText += "## Update Type Classification`n`n"
    $helpText += "Security: Updates that address CVEs or contain security fixes/patches`n"
    $helpText += "Feature/Bug Fix: Standard updates that add features or fix non-security bugs`n`n"
    $helpText += "---`n`n"
    $helpText += "## File Format`n`n"
    $helpText += "Software list files should be plain text (.txt) with one software name per line.`n`n"
    $helpText += "Example:`n"
    $helpText += "Google Chrome`n"
    $helpText += "Mozilla Firefox`n"
    $helpText += "7-Zip`n`n"
    $helpText += "---`n`n"
    $helpText += "## Troubleshooting`n`n"
    $helpText += "- If no updates appear, try increasing the days back value`n"
    $helpText += "- Use 'Test Feed' to verify PatchMyPC catalog connectivity`n"
    $helpText += "- Use 'Debug Feed' to test basic internet connection`n"
    $helpText += "- Clear history to reset the new update highlighting`n`n"
    $helpText += "---`n`n"
    $helpText += "Data Source: PatchMyPC Catalog (https://patchmypc.com)`n"
    $helpText += "Created with PowerShell and Windows Forms"

    $helpTextBox.Text = $helpText.Replace("`n", [Environment]::NewLine)

    $helpForm.Controls.Add($helpTextBox)
    $helpForm.ShowDialog()
})

# Show the form
$form.ShowDialog()