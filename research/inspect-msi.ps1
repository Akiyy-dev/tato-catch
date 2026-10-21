$ErrorActionPreference = 'Stop'
$sample = Join-Path $PSScriptRoot 'samples\TatoTalk_3.01.200343.msi'
$output = $PSScriptRoot
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($sample, 0)
function Read-MsiTable {
    param([string]$Sql, [string[]]$Fields)
    $view = $database.OpenView($Sql)
    [void]$view.Execute()
    $rows = [System.Collections.Generic.List[object]]::new()
    while ($record = $view.Fetch()) {
        $row = [ordered]@{}
        for ($index = 1; $index -le $Fields.Count; $index++) {
            $row[$Fields[$index - 1]] = $record.StringData($index)
        }
        $rows.Add([pscustomobject]$row)
    }
    [void]$view.Close()
    return $rows.ToArray()
}
$properties = @(Read-MsiTable 'SELECT `Property`, `Value` FROM `Property`' @('Property', 'Value'))
$files = @(Read-MsiTable 'SELECT `File`, `Component_`, `FileName`, `FileSize`, `Version`, `Language`, `Attributes`, `Sequence` FROM `File`' @('File', 'Component', 'FileName', 'FileSize', 'Version', 'Language', 'Attributes', 'Sequence'))
$media = @(Read-MsiTable 'SELECT `DiskId`, `LastSequence`, `Cabinet` FROM `Media`' @('DiskId', 'LastSequence', 'Cabinet'))
$customActions = @(Read-MsiTable 'SELECT `Action`, `Type` FROM `CustomAction`' @('Action', 'Type'))
$streams = @(Read-MsiTable 'SELECT `Name` FROM `_Streams`' @('Name'))
$tables = @(Read-MsiTable 'SELECT `Name` FROM `_Tables`' @('Name'))
$report = [ordered]@{
    checkedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    sourceUrl = 'https://ttkdesk.shxcox.com/win/TatoTalk_3.01.200343.msi'
    samplePath = $sample
    fileSize = (Get-Item -LiteralPath $sample).Length
    sha256 = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
    method = 'Read-only MSI database access through WindowsInstaller COM OpenDatabase(..., 0). No MSI installation, custom action execution, application execution, profile or conversation reads.'
    productProperties = @($properties | Where-Object { $_.Property -in @('ProductName','ProductVersion','Manufacturer','ProductLanguage','ProductCode','UpgradeCode','ALLUSERS','MSIINSTALLPERUSER','INSTALLDIR') })
    files = $files
    media = $media
    customActionNamesAndTypesOnly = $customActions
    streamNames = $streams
    tableNames = $tables
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'windows-triage.json') -Encoding UTF8
[pscustomobject]@{ product = $report.productProperties; fileCount = $files.Count; files = $files; media = $media; customActions = $customActions; streams = $streams; sha256 = $report.sha256 } | ConvertTo-Json -Depth 8
