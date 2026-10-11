[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('DefaultWindowsDriverPolicy', 'LivingOffTheLandDriversPolicy')]
  [string]$Setup,
  [Parameter(Mandatory = $true)]
  [ValidateSet('Audit', 'Enforce')]
  [string]$Mode
)

$ErrorActionPreference = 'Stop'

function Read-WdacPolicy {
  param([Parameter(Mandatory = $true)][string]$PolicyPath)

  $settings = New-Object System.Xml.XmlReaderSettings
  $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
  $settings.XmlResolver = $null
  $reader = [System.Xml.XmlReader]::Create($PolicyPath, $settings)
  try {
    $policy = New-Object System.Xml.XmlDocument
    $policy.PreserveWhitespace = $true
    $policy.XmlResolver = $null
    $policy.Load($reader)
    return ,$policy
  }
  finally { $reader.Dispose() }
}

function New-WdacNamespaceManager {
  param([Parameter(Mandatory = $true)][System.Xml.XmlDocument]$Policy)

  $manager = New-Object System.Xml.XmlNamespaceManager($Policy.NameTable)
  $manager.AddNamespace('p', 'urn:schemas-microsoft-com:sipolicy')
  return ,$manager
}

function Read-LolDriversFeed {
  param([Parameter(Mandatory = $true)][string]$Path)

  $json = [IO.File]::ReadAllText($Path)
  if (-not $json.TrimStart().StartsWith('[')) {
    throw 'Expected a LOLDrivers JSON array.'
  }
  # Dictionaries preserve case-sensitive PE section names on both PS editions.
  if ($PSVersionTable.PSVersion.Major -ge 6) {
    return ,(ConvertFrom-Json -InputObject $json -AsHashtable)
  }
  Add-Type -AssemblyName System.Web.Extensions
  $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
  $serializer.MaxJsonLength = [int]::MaxValue
  return ,($serializer.DeserializeObject($json))
}

function Set-WdacVersion {
  param([System.Xml.XmlDocument]$Policy, [string]$Version)

  $ns = New-WdacNamespaceManager -Policy $Policy
  $node = $Policy.SelectSingleNode('/p:SiPolicy/p:VersionEx', $ns)
  if (-not $node) { throw 'XML is missing VersionEx.' }
  $previous = $node.InnerText
  $node.InnerText = $Version
  $setting = $Policy.SelectSingleNode('/p:SiPolicy/p:Settings/p:Setting[@Provider="PolicyInfo" and @ValueName="Id"]/p:Value/p:String', $ns)
  if ($setting -and $setting.InnerText -eq $previous) {
    $setting.InnerText = $Version
  }
}

function Update-WdacDeploymentVersion {
  param([System.Xml.XmlDocument]$Policy, [string]$PolicyId,
    [string]$PolicyDirectory, [string[]]$RecordNames, [string]$WorkingXml)

  # Both setups can share Microsoft's PolicyID. Keep the version above prior
  # local deployment records so switching setups does not stage an older policy.
  $highestVersion = [version]$policy.SiPolicy.VersionEx
  foreach ($recordName in $recordNames) {
    $recordPath = Join-Path $PolicyDirectory $recordName
    if (Test-Path -LiteralPath $recordPath) {
      $record = Read-WdacPolicy -PolicyPath $recordPath
      if ([string]$record.SiPolicy.PolicyID -eq $policyId -and
          [version]$record.SiPolicy.VersionEx -gt $highestVersion) {
        $highestVersion = [version]$record.SiPolicy.VersionEx
      }
    }
  }
  Set-WdacVersion -Policy $policy -Version $highestVersion.ToString()
  $null = Save-WdacPolicy -Policy $policy -PolicyPath $workingXml
}

function Publish-WdacSourcePolicy {
  param([string]$WorkingXml, [string]$PolicyPath,
    [string]$PolicyDirectory, [string]$BackupDirectory)

  # Publish new XML only after successful compilation, including first run.
  $pending = Join-Path $PolicyDirectory ([IO.Path]::GetRandomFileName())
  try {
    Copy-Item -LiteralPath $workingXml -Destination $pending
    if (Test-Path -LiteralPath $policyPath) {
      $backup = Join-Path $backupDirectory 'DriverPolicy_Enforced.xml.bak'
      [IO.File]::Replace($pending, $policyPath, $backup)
      Write-Host "Source XML backup saved as: $backup"
    }
    else {
      [IO.File]::Move($pending, $policyPath)
      Write-Host "Source XML saved as: $policyPath"
    }
  }
  finally {
    if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending -Force }
  }
}

function Remove-WdacLegacyFiles {
  param([string]$PolicyDirectory, [string]$Destination,
    [string]$BackupDirectory, [string[]]$RecordNames, [string]$PolicyId)

  Write-Host 'Cleaning up previous generated files...'
  try {
    foreach ($folder in @($PolicyDirectory, [IO.Path]::GetDirectoryName($destination))) {
      $backupName = if ($folder -eq $PolicyDirectory) { 'DriverPolicy_Enforced.xml' } else { [IO.Path]::GetFileName($destination) }
      $pattern = '^' + [regex]::Escape($backupName) + '\.bak\.[0-9a-f]{32}$'
      $oldBackups = @(Get-ChildItem -LiteralPath $folder -File | Where-Object { $_.Name -match $pattern } | Sort-Object LastWriteTimeUtc -Descending)
      $retainedBackup = Join-Path $backupDirectory ($backupName + '.bak')
      if ($oldBackups.Count -and -not (Test-Path -LiteralPath $retainedBackup)) {
        Copy-Item -LiteralPath $oldBackups[0].FullName -Destination $retainedBackup
      }
      foreach ($file in $oldBackups) {
        Remove-Item -LiteralPath $file.FullName -Force
      }
    }
    foreach ($recordName in $recordNames | Where-Object { $_ -like '*-applied.xml' }) {
      $recordPath = Join-Path $PolicyDirectory $recordName
      if (Test-Path -LiteralPath $recordPath) {
        $record = Read-WdacPolicy -PolicyPath $recordPath
        if ([string]$record.SiPolicy.PolicyID -eq $policyId) { Remove-Item -LiteralPath $recordPath -Force }
      }
    }
  }
  catch { Write-Warning "Policy installed, but old-file cleanup failed: $_" }
}

function Assert-WdacPrerequisites {
  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from Windows PowerShell as Administrator.'
  }
  $osVersion = [Environment]::OSVersion.Version
  if ($osVersion.Major -lt 10) { throw 'Windows 10 or later is required.' }
  if ($osVersion.Build -lt 18362) { throw 'Windows 10 version 1903 or later is required.' }
  try {
    Import-Module ConfigCI -Global -ErrorAction Stop
    $null = Get-Command ConvertFrom-CIPolicy -ErrorAction Stop
  }
  catch { throw 'ConfigCI is unavailable. Use Windows PowerShell 5.1 with the Windows ConfigCI module installed.' }
}

function Add-PolicyChild {
  param([System.Xml.XmlElement]$Parent, [System.Xml.XmlElement]$Child, [string]$Indent)
  $last = $Parent.LastChild
  if ($last -and $last.NodeType -in @('Whitespace', 'SignificantWhitespace')) {
    [void]$Parent.InsertBefore($Parent.OwnerDocument.CreateWhitespace("`r`n$Indent"), $last)
    [void]$Parent.InsertBefore($Child, $last)
  }
  else {
    [void]$Parent.AppendChild($Parent.OwnerDocument.CreateWhitespace("`r`n$Indent"))
    [void]$Parent.AppendChild($Child)
  }
}

function Update-LolDriversPolicy {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$PolicyPath,
    [string]$JsonPath,
    [string]$SkippedReportPath
  )

  $ErrorActionPreference = 'Stop'
  $policyFile = (Resolve-Path -LiteralPath $PolicyPath).ProviderPath
  $downloadFile = $null
  try {
    if ($JsonPath) {
      $feedFile = (Resolve-Path -LiteralPath $JsonPath).ProviderPath
    }
    else {
      $downloadFile = [IO.Path]::GetTempFileName()
      $feedFile = $downloadFile
      Get-WdacDownload -Uri 'https://www.loldrivers.io/api/drivers.json' -Destination $feedFile
    }

    Write-Host 'Reading and parsing LOLDrivers feed...'
    $feed = Read-LolDriversFeed -Path $feedFile
    Write-Host ('Parsed {0} driver entries. Merging rules...' -f @($feed).Count)

    Write-Host "Reading policy XML: $policyFile"
    $policy = Read-WdacPolicy -PolicyPath $policyFile
    $namespaceUri = $policy.DocumentElement.NamespaceURI
    $ns = New-WdacNamespaceManager -Policy $policy
    $fileRules = $policy.SelectSingleNode('/p:SiPolicy/p:FileRules', $ns)
    $driverSigners = $policy.SelectNodes('/p:SiPolicy/p:SigningScenarios/p:SigningScenario[@Value="131"]/p:ProductSigners', $ns)
    if (-not $fileRules -or $driverSigners.Count -ne 1) {
      throw 'XML must contain FileRules and exactly one kernel-mode (131) ProductSigners section.'
    }

    $hashRules = @{}
    $usedIds = @{}
    foreach ($node in $policy.SelectNodes('//*[@ID]')) {
      $id = $node.GetAttribute('ID')
      if ($usedIds.ContainsKey($id)) { throw "Duplicate XML rule ID: $id" }
      $usedIds[$id] = $true
    }
    foreach ($node in $fileRules.SelectNodes('p:Deny[@Hash]', $ns)) {
      # Reuse unconditional hash denies only; a restricted deny may not match.
      if ($node.Attributes.Count -eq 3 -and $node.HasAttribute('FriendlyName')) {
        $hashRules[$node.GetAttribute('Hash').ToUpperInvariant()] = $node.GetAttribute('ID')
      }
      elseif ($node.Attributes.Count -eq 2) {
        $hashRules[$node.GetAttribute('Hash').ToUpperInvariant()] = $node.GetAttribute('ID')
      }
    }
    $references = $driverSigners[0].SelectSingleNode('p:FileRulesRef', $ns)
    $usedRefs = @{}
    if ($references) {
      foreach ($node in $references.SelectNodes('p:FileRuleRef', $ns)) {
        $usedRefs[$node.GetAttribute('RuleID')] = $true
      }
    }

    $added = 0
    $linked = 0
    $samples = 0
    $withoutHashes = 0
    $invalidHashes = 0
    $validHashes = 0
    $skippedDrivers = New-Object 'System.Collections.Generic.List[object]'
    foreach ($entry in $feed) {
      if ($entry -isnot [System.Collections.IDictionary] -or
          -not $entry.ContainsKey('KnownVulnerableSamples')) {
        throw 'Feed entry is missing KnownVulnerableSamples.'
      }
      foreach ($sample in $entry['KnownVulnerableSamples']) {
        if ($sample -isnot [System.Collections.IDictionary]) {
          throw 'Expected a dictionary for each KnownVulnerableSamples entry.'
        }
        $samples++
        $hasHash = $false
        $sampleInvalidHashes = 0
        $auth = $sample['Authentihash']
        $label = [string]$sample['Filename']
        if (-not $label) { $label = [string]$sample['OriginalFilename'] }
        if (-not $label) { $label = [string]$entry['Id'] }
        foreach ($algorithm in @('SHA256', 'SHA1')) {
          if ($auth -isnot [System.Collections.IDictionary]) { continue }
          $hash = ([string]$auth[$algorithm]).Trim().ToUpperInvariant()
          if (-not $hash) { continue }
          $length = if ($algorithm -eq 'SHA256') { 64 } else { 40 }
          if ($hash -notmatch "\A[0-9A-F]{$length}\z") {
            $invalidHashes++
            $sampleInvalidHashes++
            continue
          }
          $hasHash = $true
          $validHashes++
          if ($hashRules.ContainsKey($hash)) {
            $ruleId = $hashRules[$hash]
          }
          else {
            $ruleId = "ID_DENY_LOLDRIVERS_${algorithm}_$hash"
            if ($usedIds.ContainsKey($ruleId)) { throw "Conflicting XML rule ID: $ruleId" }
            $deny = $policy.CreateElement('Deny', $namespaceUri)
            $deny.SetAttribute('ID', $ruleId)
            $deny.SetAttribute('FriendlyName', "LOLDrivers $label Authenticode $algorithm")
            $deny.SetAttribute('Hash', $hash)
            Add-PolicyChild -Parent $fileRules -Child $deny -Indent '    '
            $hashRules[$hash] = $ruleId
            $usedIds[$ruleId] = $true
            $added++
          }
          if (-not $usedRefs.ContainsKey($ruleId)) {
            if (-not $references) {
              $references = $policy.CreateElement('FileRulesRef', $namespaceUri)
              [void]$driverSigners[0].AppendChild($references)
            }
            $reference = $policy.CreateElement('FileRuleRef', $namespaceUri)
            $reference.SetAttribute('RuleID', $ruleId)
            Add-PolicyChild -Parent $references -Child $reference -Indent '          '
            $usedRefs[$ruleId] = $true
            $linked++
          }
        }
        if (-not $hasHash) {
          $withoutHashes++
          $skippedDrivers.Add([pscustomobject][ordered]@{
            EntryId = [string]$entry['Id']
            Filename = $label
            SHA256 = [string]$sample['SHA256']
            Reason = if ($sampleInvalidHashes) { 'No usable Authenticode SHA256/SHA1 hash; malformed hash present.' } else { 'Missing Authenticode SHA256/SHA1 hashes.' }
          })
        }
      }
    }
    if (-not $SkippedReportPath) {
      $SkippedReportPath = Join-Path ([IO.Path]::GetDirectoryName($policyFile)) 'WDAC\LOLDrivers-Skipped.csv'
    }
    $SkippedReportPath = [IO.Path]::GetFullPath($SkippedReportPath)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($SkippedReportPath))
    if ($skippedDrivers.Count) {
      $skippedDrivers | Export-Csv -LiteralPath $SkippedReportPath -NoTypeInformation -Encoding UTF8
    }
    else {
      # Replace any previous report with a header-only CSV when nothing was skipped.
      '"EntryId","Filename","SHA256","Reason"' | Set-Content -LiteralPath $SkippedReportPath -Encoding UTF8
    }
    Write-Host "Skipped LOLDrivers samples report: $SkippedReportPath"
    if ($validHashes -eq 0) { throw 'Feed contains no valid Authenticode SHA256/SHA1 hashes. XML was not updated.' }
    if ($withoutHashes) { Write-Warning "$withoutHashes of $samples samples have no usable Authenticode hash and were skipped. Flat file hashes are not substituted." }
    if ($invalidHashes) { Write-Warning "$invalidHashes malformed Authenticode hashes were skipped." }

    $backupPath = $null
    if ($added -gt 0 -or $linked -gt 0) {
      $backupPath = Save-WdacPolicy -Policy $policy -PolicyPath $policyFile
    }
    Write-Host "LOLDrivers: $samples samples; $added new deny rules; $linked new driver references."
    [pscustomobject]@{
      PolicyPath = $policyFile
      Samples = $samples
      AddedRules = $added
      AddedReferences = $linked
      SkippedSamples = $withoutHashes
      SkippedReportPath = $SkippedReportPath
      InvalidHashes = $invalidHashes
      BackupPath = $backupPath
    }
  }
  finally {
    foreach ($temporaryPath in @($downloadFile)) {
      if ($temporaryPath -and (Test-Path -LiteralPath $temporaryPath)) {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

function Set-WdacPolicyMode {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$PolicyPath,
    [Parameter(Mandatory = $true)][ValidateSet('Audit', 'Enforce')][string]$Mode
  )
  $ErrorActionPreference = 'Stop'
  $policyFile = (Resolve-Path -LiteralPath $PolicyPath).ProviderPath
  $policy = Read-WdacPolicy -PolicyPath $policyFile
  $ns = New-WdacNamespaceManager -Policy $policy
  $rules = $policy.SelectSingleNode('/p:SiPolicy/p:Rules', $ns)
  if (-not $rules) { throw 'XML is missing the WDAC Rules element.' }
  $auditRules = $rules.SelectNodes('p:Rule[p:Option="Enabled:Audit Mode"]', $ns)
  if (($Mode -eq 'Audit' -and $auditRules.Count -eq 1) -or
      ($Mode -eq 'Enforce' -and $auditRules.Count -eq 0)) { return }

  foreach ($rule in $auditRules) { [void]$rules.RemoveChild($rule) }
  if ($Mode -eq 'Audit') {
    $rule = $policy.CreateElement('Rule', $policy.DocumentElement.NamespaceURI)
    $option = $policy.CreateElement('Option', $policy.DocumentElement.NamespaceURI)
    $option.InnerText = 'Enabled:Audit Mode'
    [void]$rule.AppendChild($option)
    [void]$rules.AppendChild($policy.CreateWhitespace("`r`n    "))
    [void]$rules.AppendChild($rule)
  }
  Save-WdacPolicy -Policy $policy -PolicyPath $policyFile
}

function Save-WdacPolicy {
  param([System.Xml.XmlDocument]$Policy, [string]$PolicyPath)
  $ErrorActionPreference = 'Stop'
  $ns = New-WdacNamespaceManager -Policy $Policy
  $versionNode = $Policy.SelectSingleNode('/p:SiPolicy/p:VersionEx', $ns)
  if (-not $versionNode) { throw 'XML is missing VersionEx.' }
  $oldVersion = $versionNode.InnerText
  $version = [version]$oldVersion
  $parts = @($version.Major, $version.Minor, $version.Build, $version.Revision)
  if (@($parts | Where-Object { $_ -lt 0 -or $_ -gt 65535 }).Count) {
    throw 'VersionEx must have four components in the range 0..65535.'
  }
  $position = 3
  while ($position -ge 0 -and $parts[$position] -eq 65535) {
    $parts[$position] = 0
    $position--
  }
  if ($position -lt 0) { throw 'Policy version cannot be incremented.' }
  $parts[$position]++
  Set-WdacVersion -Policy $Policy -Version ($parts -join '.')
  $pending = Join-Path ([IO.Path]::GetDirectoryName($PolicyPath)) ([IO.Path]::GetRandomFileName())
  try {
    $Policy.Save($pending)
    $backup = $PolicyPath + '.bak'
    [IO.File]::Replace($pending, $PolicyPath, $backup)
    return $backup
  }
  finally {
    if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending -Force }
  }
}

function Get-WdacDownload {
  param([string]$Uri, [string]$Destination)
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  $previousTls = [Net.ServicePointManager]::SecurityProtocol
  try {
    if ($PSVersionTable.PSVersion.Major -le 5) {
      [Net.ServicePointManager]::SecurityProtocol = $previousTls -bor [Net.SecurityProtocolType]::Tls12
    }
    Write-Host "Downloading $Uri..."
    Invoke-WebRequest -Uri $Uri -OutFile $Destination -UseBasicParsing -TimeoutSec 0 -ErrorAction Stop
    Write-Host ('Download complete: {0:N1} MB.' -f ((Get-Item -LiteralPath $Destination).Length / 1MB))
  }
  finally {
    [Net.ServicePointManager]::SecurityProtocol = $previousTls
  }
}

function Install-WdacBinary {
  param([string]$BinaryPath, [string]$Destination, [string]$BackupDirectory)
  $ErrorActionPreference = 'Stop'
  $binary = Get-Item -LiteralPath $BinaryPath
  if ($binary.Length -eq 0) { throw 'The prepared policy binary is empty.' }
  $destinationFolder = [IO.Path]::GetDirectoryName($Destination)
  if (-not (Test-Path -LiteralPath $destinationFolder)) {
    [void](New-Item -Path $destinationFolder -ItemType Directory -Force)
  }
  if (Test-Path -LiteralPath $Destination) {
    $backup = Join-Path $BackupDirectory ([IO.Path]::GetFileName($Destination) + '.bak')
    Copy-Item -LiteralPath $Destination -Destination $backup -Force
    Write-Host "Previous binary backed up as: $backup"
  }
  Write-Host "Installing policy binary: $Destination"
  Copy-Item -LiteralPath $BinaryPath -Destination $Destination -Force
  Write-Host "Policy installed at: $Destination"
}

function Get-MicrosoftDriverPolicy {
  param([string]$StageDirectory, [string]$Destination)
  $ErrorActionPreference = 'Stop'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archivePath = Join-Path $StageDirectory 'MicrosoftDriverBlocklist.zip'
  Get-WdacDownload -Uri 'https://aka.ms/VulnerableDriverBlockList' -Destination $archivePath
  Write-Host 'Reading Microsoft archive and extracting DriverPolicy_Enforced.xml...'
  $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
  try {
    $entries = @($archive.Entries | Where-Object { $_.Name -eq 'DriverPolicy_Enforced.xml' })
    if ($entries.Count -ne 1 -or $entries[0].Length -eq 0) {
      throw 'Microsoft archive must contain exactly one nonempty DriverPolicy_Enforced.xml.'
    }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $Destination)
  }
  finally { $archive.Dispose() }
}

function Invoke-WdacSetup {
  param(
    [ValidateSet('DefaultWindowsDriverPolicy', 'LivingOffTheLandDriversPolicy')][string]$Setup,
    [ValidateSet('Audit', 'Enforce')][string]$Mode,
    [string]$PolicyDirectory = $PSScriptRoot,
    [string]$WindowsDirectory = $env:windir
  )
  $ErrorActionPreference = 'Stop'
  $stateDirectory = Join-Path $PolicyDirectory 'WDAC'
  $backupDirectory = Join-Path $stateDirectory 'Backups'
  $appliedXml = Join-Path $stateDirectory 'AppliedPolicy.xml'
  $stage = Join-Path $PolicyDirectory ('.wdac-stage-' + [guid]::NewGuid().ToString('N'))
  [void](New-Item -Path $stage -ItemType Directory)
  try {
    $policyPath = Join-Path $PolicyDirectory 'DriverPolicy_Enforced.xml'
    $workingXml = Join-Path $stage 'DriverPolicy.xml'
    if ($Setup -eq 'DefaultWindowsDriverPolicy' -or -not (Test-Path -LiteralPath $policyPath)) {
      Get-MicrosoftDriverPolicy -StageDirectory $stage -Destination $workingXml
    }
    else {
      Write-Host "Reading source policy XML: $policyPath"
      Copy-Item -LiteralPath $policyPath -Destination $workingXml
    }
    if ($Setup -eq 'LivingOffTheLandDriversPolicy') {
      $null = Update-LolDriversPolicy -PolicyPath $workingXml -SkippedReportPath (Join-Path $stateDirectory 'LOLDrivers-Skipped.csv')
    }
    Write-Host "Preparing $Setup in $Mode mode..."
    $null = Set-WdacPolicyMode -PolicyPath $workingXml -Mode $Mode
    $policy = Read-WdacPolicy -PolicyPath $workingXml
    $policyGuid = [guid]::Empty
    if (-not [guid]::TryParse([string]$policy.SiPolicy.PolicyID, [ref]$policyGuid)) {
      throw 'DriverPolicy_Enforced.xml must contain a valid multiple-policy PolicyID.'
    }
    $policyId = '{' + $policyGuid.ToString().ToUpperInvariant() + '}'
    $recordNames = @('DriverPolicy_Enforced.xml', 'WDAC\AppliedPolicy.xml',
      'DefaultWindowsDriverPolicy-Audit-applied.xml', 'DefaultWindowsDriverPolicy-Enforce-applied.xml',
      'LivingOffTheLandDriversPolicy-Audit-applied.xml', 'LivingOffTheLandDriversPolicy-Enforce-applied.xml')
    Update-WdacDeploymentVersion -Policy $policy -PolicyId $policyId -PolicyDirectory $PolicyDirectory -RecordNames $recordNames -WorkingXml $workingXml
    $binaryPath = Join-Path $stage "$policyId.cip"
    Write-Host 'Compiling WDAC policy...'
    ConvertFrom-CIPolicy -XmlFilePath $workingXml -BinaryFilePath $binaryPath -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $binaryPath) -or (Get-Item -LiteralPath $binaryPath).Length -eq 0) {
      throw 'Policy compilation did not produce a nonempty binary.'
    }
    Write-Host 'Compilation complete.'
    [void][IO.Directory]::CreateDirectory($backupDirectory)
    if ($Setup -eq 'LivingOffTheLandDriversPolicy') {
      Publish-WdacSourcePolicy -WorkingXml $workingXml -PolicyPath $policyPath -PolicyDirectory $PolicyDirectory -BackupDirectory $backupDirectory
    }
    $destination = Join-Path $WindowsDirectory "System32\CodeIntegrity\CIPolicies\Active\$policyId.cip"
    Install-WdacBinary -BinaryPath $binaryPath -Destination $destination -BackupDirectory $backupDirectory
    Write-Host "Saving applied policy XML: $appliedXml"
    Copy-Item -LiteralPath $workingXml -Destination $appliedXml -Force
    Remove-WdacLegacyFiles -PolicyDirectory $PolicyDirectory -Destination $destination -BackupDirectory $backupDirectory -RecordNames $recordNames -PolicyId $policyId
    Write-Host "$Setup installed in $Mode mode. Reboot to apply the policy."
  }
  finally {
    # Delete only this invocation's own staging directory beside the script.
    $resolvedStage = [IO.Path]::GetFullPath($stage)
    $expectedPrefix = Join-Path ([IO.Path]::GetFullPath($PolicyDirectory)) '.wdac-stage-'
    if ($resolvedStage.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
  }
}

Assert-WdacPrerequisites

Invoke-WdacSetup -Setup $Setup -Mode $Mode
