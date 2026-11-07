Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(866)
    $OutputEncoding = [System.Text.Encoding]::GetEncoding(866)
} catch {
    # Игнорируем ошибку при работе без консоли (в EXE)
}

# Проверка прав Администратора
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$cryptoPath = "${env:ProgramFiles}\Crypto Pro\CSP"
if (-not (Test-Path "$cryptoPath\certmgr.exe")) {
    $cryptoPath = "${env:ProgramFiles(x86)}\Crypto Pro\CSP"
}
$certmgr = "$cryptoPath\certmgr.exe"
$csptest = "$cryptoPath\csptest.exe"

if (-not (Test-Path $certmgr)) {
    [System.Windows.Forms.MessageBox]::Show("КриптоПро CSP не найден на этом ПК!", "Ошибка", "OK", "Error")
    return
}

$certList = @()
$foundContainers = @{}
$now = Get-Date

# 1. Чтение сертификатов из хранилищ Windows
$stores = @(
    @{ Name = "uMy";   Title = "Личные (Пользователь)" },
    @{ Name = "mMy";   Title = "Личные (Компьютер)" },
    @{ Name = "uCA";   Title = "Промежуточные (Пользователь)" },
    @{ Name = "mCA";   Title = "Промежуточные (Компьютер)" },
    @{ Name = "uROOT"; Title = "Доверенные (Пользователь)" },
    @{ Name = "mROOT"; Title = "Доверенные (Компьютер)" }
)

foreach ($store in $stores) {
    $rawOutput = & $certmgr -list -store $store.Name 2>&1
    if (-not $rawOutput) { continue }
    $rawText = $rawOutput -join "`n"
    $blocks = $rawText -split '(?m)^(?=\s*\d+[-=]+|\s*={3,})'
    
    foreach ($block in $blocks) {
        $thumbprint = $null
        if ($block -match '(?i)(?:SHA1|отпечаток|Fingerprint|Hash).*?:\s*([a-fA-F0-9]{40})') {
            $thumbprint = $Matches[1]
        } elseif ($block -match '([a-fA-F0-9]{40})') {
            $thumbprint = $Matches[1]
        }
        if (-not $thumbprint) { continue }

        $container = ""
        if ($block -match '(?i)(?:Container|Контейнер|Имя контейнера)\s*:\s*(.+)') {
            $container = $Matches[1].Trim()
            $cleanName = ($container -replace '.*?\\', '').ToLower()
            $foundContainers[$cleanName] = $true
        }

        $subject = "Неизвестный владелец"
        if ($block -match 'CN=([^,\r\n]+)') { 
            $subject = $Matches[1].Trim() 
        } elseif ($block -match '(?i)(?:Subject|Субъект)\s*:\s*(.+)') { 
            $subject = $Matches[1].Trim() 
        }

        # --- "Кому выдан": имя = компонент CN= из строки Subject (в ЛЮБОМ месте), без мусора C=RU / ИНН ---
        $subjectLine = ""
        if ($block -match '(?i)(?:Subject|Субъект)\s*:\s*(.+)') { $subjectLine = $Matches[1].Trim() }
        $cnRaw = ""
        if ($subjectLine -match '(?i)CN\s*=\s*([^,;]+)') {
            # чистим обрамляющие/удвоенные кавычки: CN="ООО ""ИМЯ""" -> ООО "ИМЯ"
            $cnRaw = $Matches[1].Trim().Trim('"').Replace('""','"')
        }
        if ([string]::IsNullOrWhiteSpace($cnRaw)) { $cnRaw = $subject }

        # Дата выдачи (Not valid before / Выдан)
        $issuedOn = ""
        if ($block -match '(?i)(?:Not valid before|Выдан|Valid from)\s*[:\s]+.*?(\d{2}[\./]\d{2}[\./]\d{4}\s+\d{2}:\d{2}:\d{2})') {
            $issuedOn = ($Matches[1] -replace '/', '.').Trim()
        } elseif ($block -match '(?i)(?:Not valid before|Выдан|Valid from)\s*[:\s]+.*?(\d{2}[\./]\d{2}[\./]\d{4})') {
            $issuedOn = ($Matches[1] -replace '/', '.').Trim()
        }

        $validToStr = "Неизвестно"
        $isExpired = $false
        $dateMatch = $null
        
        if ($block -match '(?i)(?:Not valid after|Истекает|Valid to|До)\s*[:\s]+.*?(\d{2}[\./]\d{2}[\./]\d{4})') {
            $dateMatch = $Matches[1]
        }
        elseif ($block -match '\b(\d{2}[\./]\d{2}[\./]\d{4})\b') {
            $dateMatch = $Matches[1]
        }

        if ($dateMatch) {
            $dateOnly = $dateMatch -replace '/', '.'
            try {
                $validToDate = [datetime]::ParseExact($dateOnly, "dd.MM.yyyy", $null)
                $validToStr = $validToDate.ToString("dd.MM.yyyy")
                if ($validToDate -lt $now) { $isExpired = $true }
            } catch {
                $validToStr = $dateOnly
            }
        }

        $certList += [PSCustomObject]@{
            Store      = $store.Title
            StoreCode  = $store.Name
            Subject    = $subject
            CnRaw      = $cnRaw
            IssuedOn   = $issuedOn
            ValidTo    = $validToStr
            IsExpired  = $isExpired
            Container  = $container
            Thumbprint = $thumbprint
            RegPath    = $null
        }
    }
}

# 2. Сканирование реестра
$regTargetPaths = @(
    "HKCU:\Software\Crypto Pro\Settings\Users",
    "HKLM:\SOFTWARE\Crypto Pro\Settings\Users",
    "HKLM:\SOFTWARE\WOW6432Node\Crypto Pro\Settings\Users"
)

foreach ($basePath in $regTargetPaths) {
    if (-not (Test-Path $basePath)) { continue }
    Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue | ForEach-Object {
        $keysDir = Join-Path $_.PSPath "Keys"
        if (Test-Path $keysDir) {
            Get-ChildItem -Path $keysDir -ErrorAction SilentlyContinue | ForEach-Object {
                $cName = $_.PSChildName
                $cLower = $cName.ToLower()
                if (-not $foundContainers.ContainsKey($cLower)) {
                    $foundContainers[$cLower] = $true
                    $regContainerName = "REGISTRY\\$cName"
                    $cSubject = "[Осиротевший контейнер]"
                    $cValidToStr = "—"
                    $cExpired = $true
                    $cCnRaw = "[Осиротевший контейнер]"
                    $cIssuedOn = ""

                    $cOutput = & $certmgr -list -container "$regContainerName" 2>&1
                    if ($cOutput) {
                        $cText = $cOutput -join "`n"
                        if ($cText -match 'CN=([^,\r\n]+)') { 
                            $cSubject = $Matches[1].Trim() 
                        } elseif ($cText -match '(?i)(?:Subject|Субъект)\s*:\s*(.+)') { 
                            $cSubject = $Matches[1].Trim() 
                        }

                        # "Кому выдан" для контейнера реестра: CN= в любом месте
                        $cSubjectLine = ""
                        if ($cText -match '(?i)(?:Subject|Субъект)\s*:\s*(.+)') { $cSubjectLine = $Matches[1].Trim() }
                        $cCnRaw = ""
                        if ($cSubjectLine -match '(?i)CN\s*=\s*([^,;]+)') {
                            $cCnRaw = $Matches[1].Trim().Trim('"').Replace('""','"')
                        }
                        if ([string]::IsNullOrWhiteSpace($cCnRaw)) { $cCnRaw = $cSubject }

                        if ($cText -match '(?i)(?:Not valid before|Выдан|Valid from)\s*[:\s]+.*?(\d{2}[\./]\d{2}[\./]\d{4}\s+\d{2}:\d{2}:\d{2})') {
                            $cIssuedOn = ($Matches[1] -replace '/', '.').Trim()
                        } elseif ($cText -match '(?i)(?:Not valid before|Выдан|Valid from)\s*[:\s]+.*?(\d{2}[\./]\d{2}[\./]\d{4})') {
                            $cIssuedOn = ($Matches[1] -replace '/', '.').Trim()
                        }

                        $cDateMatch = $null
                        if ($cText -match '(?i)(?:Not valid after|Истекает|Valid to|До)\s*[:\s]+.*?(\d{2}[\./]\d{2}[\./]\d{4})') {
                            $cDateMatch = $Matches[1]
                        }
                        elseif ($cText -match '\b(\d{2}[\./]\d{2}[\./]\d{4})\b') {
                            $cDateMatch = $Matches[1]
                        }

                        if ($cDateMatch) {
                            $cDateOnly = $cDateMatch -replace '/', '.'
                            try {
                                $cValidToDate = [datetime]::ParseExact($cDateOnly, "dd.MM.yyyy", $null)
                                $cValidToStr = $cValidToDate.ToString("dd.MM.yyyy")
                                if ($cValidToDate -ge $now) { 
                                    $cExpired = $false 
                                }
                            } catch {
                                $cValidToStr = $cDateOnly
                            }
                        }
                    }

                    $certList += [PSCustomObject]@{
                        Store      = "Реестр Windows"
                        StoreCode  = "REG"
                        Subject    = $cSubject
                        CnRaw      = $cCnRaw
                        IssuedOn   = $cIssuedOn
                        ValidTo    = $cValidToStr
                        IsExpired  = $cExpired
                        Container  = $regContainerName
                        Thumbprint = ""
                        RegPath    = $_.PSPath
                    }
                }
            }
        }
    }
}

if ($certList.Count -eq 0) {
    [System.Windows.Forms.MessageBox]::Show("Сертификаты и контейнеры не найдены.", "Информация", "OK", "Information")
    return
}

# 3. Графический интерфейс
$form = New-Object System.Windows.Forms.Form
$titleAdmin = if ($isAdmin) { "[Администратор]" } else { "[Обычный пользователь]" }
$form.Text = "Очистка КриптоПро $titleAdmin"
$form.Size = New-Object System.Drawing.Size(1100, 700)
$form.MinimumSize = New-Object System.Drawing.Size(800, 500)
$form.StartPosition = "CenterScreen"

# Панель фильтров
$filterPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$filterPanel.Location = New-Object System.Drawing.Point(12, 12)
$filterPanel.Size = New-Object System.Drawing.Size(1060, 70)
$filterPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$filterPanel.FlowDirection = "LeftToRight"
$filterPanel.WrapContents = $true
$filterPanel.AutoScroll = $false

$chkPersonal = New-Object System.Windows.Forms.CheckBox
$chkPersonal.Text = "Личные (Пользователь + Компьютер)"
$chkPersonal.Width = 250
$chkPersonal.Checked = $true

$chkIntermediate = New-Object System.Windows.Forms.CheckBox
$chkIntermediate.Text = "Промежуточные (Пользователь + Компьютер)"
$chkIntermediate.Width = 280
$chkIntermediate.Checked = $false

$chkTrusted = New-Object System.Windows.Forms.CheckBox
$chkTrusted.Text = "Доверенные (Пользователь + Компьютер)"
$chkTrusted.Width = 280
$chkTrusted.Checked = $false

$chkRegistry = New-Object System.Windows.Forms.CheckBox
$chkRegistry.Text = "Реестр Windows"
$chkRegistry.Width = 180
$chkRegistry.Checked = $true

[void]$filterPanel.Controls.Add($chkPersonal)
[void]$filterPanel.Controls.Add($chkIntermediate)
[void]$filterPanel.Controls.Add($chkTrusted)
[void]$filterPanel.Controls.Add($chkRegistry)

# Таблица
$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(12, 90)
$grid.Size = New-Object System.Drawing.Size(1060, 500)
$grid.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false     # ЗАПРЕТ изменения высоты строк
$grid.RowHeadersVisible = $false
$grid.SelectionMode = "FullRowSelect"
$grid.MultiSelect = $true
$grid.AutoSizeColumnsMode = "Fill"

$grid.Add_CurrentCellDirtyStateChanged({
    if ($grid.IsCurrentCellDirty) {
        $grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
    }
})

$colCheck = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colCheck.HeaderText = "Удалить"
$colCheck.Width = 60

$colStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colStatus.HeaderText = "Статус"
$colStatus.Width = 170
$colStatus.ReadOnly = $true

$colStore = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colStore.HeaderText = "Источник"
$colStore.Width = 150
$colStore.ReadOnly = $true

$colSubject = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colSubject.HeaderText = "Владелец / Описание"
$colSubject.ReadOnly = $true

$colValid = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colValid.HeaderText = "Истекает"
$colValid.Width = 90
$colValid.ReadOnly = $true

$colContainer = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colContainer.HeaderText = "Кому выдан"
$colContainer.ReadOnly = $true

[void]$grid.Columns.Add($colCheck)
[void]$grid.Columns.Add($colStatus)
[void]$grid.Columns.Add($colStore)
[void]$grid.Columns.Add($colSubject)
[void]$grid.Columns.Add($colValid)
[void]$grid.Columns.Add($colContainer)

$allCertificates = $certList

function Apply-Filters {
    $grid.Rows.Clear()
    
    foreach ($c in $allCertificates) {
        # Категории, к которым относится сертификат (их может быть несколько!)
        $catPersonal     = $c.Store -like "Личные*"
        $catIntermediate = $c.Store -like "Промежуточные*"
        $catTrusted      = $c.Store -like "Доверенные*"
        # К "Реестр" относим и осиротевшие контейнеры, и любые сертификаты с контейнером REGISTRY\...
        $catRegistry     = ($c.Store -eq "Реестр Windows") -or ($c.Container -match '(?i)REGISTRY')

        # Показываем, если включён ХОТЯ БЫ ОДИН подходящий фильтр
        $showCert = ($catPersonal     -and $chkPersonal.Checked)     -or
                    ($catIntermediate -and $chkIntermediate.Checked) -or
                    ($catTrusted      -and $chkTrusted.Checked)      -or
                    ($catRegistry     -and $chkRegistry.Checked)
        
        if ($showCert) {
            if ($c.StoreCode -eq "REG") {
                if ($c.IsExpired) {
                    $statusText = "[!] В РЕЕСТРЕ (ПРОСРОЧЕН)"
                } else {
                    $statusText = "[OK] В РЕЕСТРЕ (ДЕЙСТВИТЕЛЕН)"
                }
            } elseif ($c.IsExpired) {
                $statusText = "[X] ПРОСРОЧЕН"
            } else {
                $statusText = "[OK] ДЕЙСТВИТЕЛЕН"
            }
            
            # "Кому выдан" = чистое имя (CN) + дата выдачи
            $issuedTo = $c.CnRaw
            if (-not [string]::IsNullOrWhiteSpace($c.IssuedOn)) {
                $issuedTo += "; Выдан: " + $c.IssuedOn
            }
            if ([string]::IsNullOrWhiteSpace($issuedTo)) { $issuedTo = $c.Subject }

            $rowIndex = $grid.Rows.Add($false, $statusText, $c.Store, $c.Subject, $c.ValidTo, $issuedTo)
            $grid.Rows[$rowIndex].Tag = $c
            # Технический путь контейнера прячем во всплывающую подсказку (наведение мыши)
            if (-not [string]::IsNullOrWhiteSpace($c.Container)) {
                $grid.Rows[$rowIndex].Cells[5].ToolTipText = $c.Container
            }
            
            if ($c.IsExpired) {
                $grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::MistyRose
                $grid.Rows[$rowIndex].DefaultCellStyle.ForeColor = [System.Drawing.Color]::DarkRed
            } else {
                $grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::Honeydew
                $grid.Rows[$rowIndex].DefaultCellStyle.ForeColor = [System.Drawing.Color]::DarkGreen
            }
        }
    }
}

$chkPersonal.Add_CheckedChanged({ Apply-Filters })
$chkIntermediate.Add_CheckedChanged({ Apply-Filters })
$chkTrusted.Add_CheckedChanged({ Apply-Filters })
$chkRegistry.Add_CheckedChanged({ Apply-Filters })

Apply-Filters

$btnSelectExpired = New-Object System.Windows.Forms.Button
$btnSelectExpired.Location = New-Object System.Drawing.Point(12, 600)
$btnSelectExpired.Size = New-Object System.Drawing.Size(270, 40)
$btnSelectExpired.Text = "Отметить все просроченные"
$btnSelectExpired.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$btnSelectExpired.Add_Click({
    $grid.EndEdit()
    foreach ($row in $grid.Rows) {
        $cert = $row.Tag
        if ($cert.IsExpired) {
            $row.Cells[0].Value = $true
        }
    }
})

$btnDelete = New-Object System.Windows.Forms.Button
$btnDelete.Location = New-Object System.Drawing.Point(812, 600)
$btnDelete.Size = New-Object System.Drawing.Size(240, 40)
$btnDelete.Text = "Удалить выбранные"
$btnDelete.BackColor = [System.Drawing.Color]::Firebrick
$btnDelete.ForeColor = [System.Drawing.Color]::White
$btnDelete.Font = New-Object System.Drawing.Font($btnDelete.Font, [System.Drawing.FontStyle]::Bold)
$btnDelete.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
$btnDelete.Add_Click({
    $grid.EndEdit()
    $toDeleteRows = @()
    foreach ($row in $grid.Rows) {
        if ($row.Cells[0].Value -eq $true) {
            $toDeleteRows += $row
        }
    }
    if ($toDeleteRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Вы ничего не выбрали!", "Предупреждение", "OK", "Warning")
        return
    }
    $msg = "Удалить выбранные объекты ($($toDeleteRows.Count) шт.)?"
    $confirm = [System.Windows.Forms.MessageBox]::Show($msg, "Подтверждение", "YesNo", "Question")
    if ($confirm -eq "Yes") {
        $successCount = 0
        $failCount = 0
        $failList = @()
        
        foreach ($row in $toDeleteRows) {
            $cert = $row.Tag
            $deleted = $false
            $errorMsg = ""
            
            try {
                # Метод 1: certmgr.exe
                if ($cert.Thumbprint -and $cert.StoreCode -ne "REG") {
                    & $certmgr -delete -store $cert.StoreCode -thumbprint $cert.Thumbprint 2>&1 | Out-Null
                    $exitCode = $LASTEXITCODE
                    
                    if ($exitCode -eq 0 -or $exitCode -eq -2146435028) {
                        $deleted = $true
                    }
                }
                
                # Метод 2: PowerShell X509Store
                if (-not $deleted -and $cert.Thumbprint) {
                    try {
                        $storeLocation = if ($cert.StoreCode -like "u*") { "CurrentUser" } else { "LocalMachine" }
                        $storeName = switch ($cert.StoreCode) {
                            "uMy" { "My" }
                            "mMy" { "My" }
                            "uCA" { "CA" }
                            "mCA" { "CA" }
                            "uROOT" { "Root" }
                            "mROOT" { "Root" }
                            default { "My" }
                        }
                        
                        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
                        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                        $certs = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                        if ($certs) {
                            $store.Remove($certs[0])
                            $deleted = $true
                        }
                        $store.Close()
                    } catch {
                        $psError = $_.Exception.Message
                        if ($psError -match "Отказано в доступе|Access denied") {
                            $deleted = $true
                        } else {
                            $errorMsg = "PowerShell: $psError"
                        }
                    }
                }
                
                # Удаляем контейнер
                if ($cert.Container) {
                    & $csptest -keyset -deletekeyset -container "$($cert.Container)" 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) { $deleted = $true }
                }
                
                # Удаляем запись реестра
                if ($cert.RegPath -and (Test-Path $cert.RegPath)) {
                    Remove-Item -Path $cert.RegPath -Recurse -Force -ErrorAction SilentlyContinue
                    if (-not (Test-Path $cert.RegPath)) { $deleted = $true }
                }
                
                if ($deleted) {
                    $successCount++
                    $grid.Rows.Remove($row)
                } else {
                    $failCount++
                    $failList += "$($cert.Subject) ($($cert.Store))`n  Причина: $errorMsg"
                }
            } catch {
                $failCount++
                $failList += "$($cert.Subject) ($($cert.Store))`n  Ошибка: $($_.Exception.Message)"
            }
        }
        
        $resultMsg = "✅ Удалено успешно: $successCount"
        
        if ($failCount -gt 0) {
            $resultMsg += "`n❌ Не удалось удалить: $failCount"
        }
        
        if ($failList.Count -gt 0) {
            $resultMsg += "`n`nОшибки:`n"
            $resultMsg += ($failList | Select-Object -First 5) -join "`n`n"
            if ($failList.Count -gt 5) {
                $resultMsg += "`n... и еще $($failList.Count - 5) ошибок"
            }
        }
        
        [System.Windows.Forms.MessageBox]::Show($resultMsg, "Результат удаления", "OK", "Information")
        
        if ($failCount -eq 0) {
            $form.Close()
        }
    }
})

[void]$form.Controls.Add($filterPanel)
[void]$form.Controls.Add($grid)
[void]$form.Controls.Add($btnSelectExpired)
[void]$form.Controls.Add($btnDelete)

# Принудительный вывод окна на передний план
$form.TopMost = $true
$form.Activate()
$form.BringToFront()

[void]$form.ShowDialog()