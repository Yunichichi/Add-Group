#requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [string]$GroupName,
    [string]$Format = "csv",              # csv | json
    [switch]$IncludeEmail,
    [switch]$IncludePrimary,
    [switch]$IncludeNested,
    [switch]$IncludeDisabled,
    [string[]]$Attributes,
    [string]$OutFolder,
    [switch]$SaveToServer,
    [string]$Language = "es"
)

function Set-ResponseHeader {
    param([string]$Name, [string]$Value)
    try {
        $ctx = [System.Web.HttpContext]::Current
        if ($ctx -and $ctx.Response) {
            $ctx.Response.Headers[$Name] = $Value
        }
    }
    catch { }
}
function Write-ResponseText {
    param([string]$Text)
    $ctx = [System.Web.HttpContext]::Current
    if ($ctx -and $ctx.Response) { $ctx.Response.Write($Text) } else { Write-Output $Text }
}
function Write-ResponseBytes {
    param([byte[]]$Bytes)
    $ctx = [System.Web.HttpContext]::Current
    if ($ctx -and $ctx.Response) { $ctx.Response.OutputStream.Write($Bytes, 0, $Bytes.Length) }
    else { [System.Console]::OpenStandardOutput().Write($Bytes, 0, $Bytes.Length) | Out-Null }
}

# Parse body JSON (POST fetch)
try {
    $ctx = [System.Web.HttpContext]::Current
    if ($ctx -and $ctx.Request -and $ctx.Request.HttpMethod -eq 'POST' -and $ctx.Request.ContentType -like 'application/json*') {
        $reader = New-Object System.IO.StreamReader($ctx.Request.InputStream, [System.Text.Encoding]::UTF8)
        $ctx.Request.InputStream.Position = 0
        $rawBody = $reader.ReadToEnd()
        if ($rawBody) {
            $body = $rawBody | ConvertFrom-Json -ErrorAction Stop
            if ($body.groupName) { $GroupName = [string]$body.groupName }
            if ($body.format) { $Format = [string]$body.format }
            if ($null -ne $body.includeEmail) { $IncludeEmail = [bool]$body.includeEmail }
            if ($null -ne $body.includePrimary) { $IncludePrimary = [bool]$body.includePrimary }
            if ($null -ne $body.includeNested) { $IncludeNested = [bool]$body.includeNested }
            if ($null -ne $body.includeDisabled) { $IncludeDisabled = [bool]$body.includeDisabled }
            if ($body.attributes) { $Attributes = @($body.attributes) }
            if ($body.outFolder) { $OutFolder = [string]$body.outFolder }
            if ($null -ne $body.saveToServer) { $SaveToServer = [bool]$body.saveToServer }
            if ($body.language) { $Language = [string]$body.language }
        }
    }
}
catch { }

# Normalize
$Format = ($Format ?? "csv").ToLowerInvariant()
if ($Format -notin @('csv', 'json')) { $Format = 'csv' }
$IncludeEmail = [bool]$IncludeEmail
$IncludePrimary = [bool]$IncludePrimary
$IncludeNested = [bool]$IncludeNested
$IncludeDisabled = [bool]$IncludeDisabled
$SaveToServer = [bool]$SaveToServer

# Validate
if ([string]::IsNullOrWhiteSpace($GroupName)) {
    $msg = if ($Language -eq 'en') { 'Error: GroupName is required.' }
    elseif ($Language -eq 'pt') { 'Erro: GroupName é obrigatório.' }
    else { 'Error: parámetro GroupName es requerido.' }
    try { $ctx = [System.Web.HttpContext]::Current; if ($ctx) { $ctx.Response.StatusCode = 400 } } catch {}
    Write-ResponseText $msg
    exit 0
}

$sanitizedGroup = $GroupName.Trim()

# AD module
try { Import-Module ActiveDirectory -ErrorAction Stop }
catch {
    try { $ctx = [System.Web.HttpContext]::Current; if ($ctx) { $ctx.Response.StatusCode = 500 } } catch {}
    Write-ResponseText "Error: ActiveDirectory module not available."
    exit 0
}

# Get group members
try {
    $memberParams = @{ Identity = $sanitizedGroup; ErrorAction = 'Stop' }
    if ($IncludeNested) { $memberParams['Recursive'] = $true }
    $rawMembers = Get-ADGroupMember @memberParams
}
catch {
    try { $ctx = [System.Web.HttpContext]::Current; if ($ctx) { $ctx.Response.StatusCode = 404 } } catch {}
    Write-ResponseText ("Error: no se encontró el grupo '{0}'." -f $sanitizedGroup)
    exit 0
}

$members = $rawMembers | Where-Object { $_.objectClass -eq 'user' }

# Base properties (incluimos manager para resolverlo)
$baseProps = @('samAccountName', 'givenName', 'sn', 'mail', 'userPrincipalName', 'displayName', 'enabled', 'manager')
$extra = @()
if ($Attributes) {
    $extra = $Attributes | Where-Object { $_ -and $_ -notin $baseProps }
}
$allProps = ($baseProps + $extra | Select-Object -Unique)

# Cache para managers (evita consultas repetidas)
$mgrCache = @{}

function Resolve-ManagerInfo {
    param([string]$ManagerDN)
    if ([string]::IsNullOrWhiteSpace($ManagerDN)) { return $null }
    if ($mgrCache.ContainsKey($ManagerDN)) { return $mgrCache[$ManagerDN] }
    try {
        $m = Get-ADUser -Identity $ManagerDN -Properties displayName, userPrincipalName, canonicalName, samAccountName -ErrorAction Stop
        $info = [PSCustomObject]@{
            ManagerDN            = $ManagerDN
            ManagerDisplayName   = $m.DisplayName
            ManagerUPN           = $m.UserPrincipalName
            ManagerAccountName   = $m.SamAccountName
            ManagerCanonicalName = $m.CanonicalName
        }
        $mgrCache[$ManagerDN] = $info
        return $info
    }
    catch {
        $info = [PSCustomObject]@{
            ManagerDN            = $ManagerDN
            ManagerDisplayName   = $null
            ManagerUPN           = $null
            ManagerAccountName   = $null
            ManagerCanonicalName = $null
        }
        $mgrCache[$ManagerDN] = $info
        return $info
    }
}

# Construir reporte
$report = foreach ($m in $members) {
    $u = $null
    try { $u = Get-ADUser -Identity $m.SamAccountName -Properties $allProps -ErrorAction Stop } catch { }
    if ($null -eq $u) { continue }
    if (-not $IncludeDisabled -and ($u.Enabled -ne $true)) { continue }

    $obj = [ordered]@{
        AccountName       = $u.SamAccountName
        FirstName         = $u.GivenName
        LastName          = $u.Sn
        Email             = $(if ($IncludeEmail) { $u.mail } else { "" })
        DisplayName       = $u.DisplayName
        UserPrincipalName = $u.UserPrincipalName
        Enabled           = $u.Enabled
    }

    # Atributos extra solicitados
    foreach ($attr in $extra) {
        try { $obj[$attr] = $u.$attr } catch { $obj[$attr] = $null }
    }

    # Resolver manager (si existe)
    if ($u.Manager) {
        $mgr = Resolve-ManagerInfo -ManagerDN $u.Manager
        # Incluimos el DN si el usuario pidió 'manager' explícitamente o siempre, para referencia
        $obj['ManagerDN'] = $mgr.ManagerDN
        $obj['ManagerDisplayName'] = $mgr.ManagerDisplayName
        $obj['ManagerAccountName'] = $mgr.ManagerAccountName
        $obj['ManagerUPN'] = $mgr.ManagerUPN
        $obj['ManagerCanonicalName'] = $mgr.ManagerCanonicalName
    }

    [PSCustomObject]$obj
}

# PrimaryGroup (opcional)
if ($IncludePrimary) {
    try {
        $grp = Get-ADGroup -Identity $sanitizedGroup -Properties primaryGroupToken
        if ($null -ne $grp -and $grp.primaryGroupToken) {
            $rid = $grp.primaryGroupToken
            $filter = "(primaryGroupID=$rid)"
            $pgusers = Get-ADUser -LDAPFilter $filter -Properties $allProps | ForEach-Object {
                if (-not $IncludeDisabled -and ($_.Enabled -ne $true)) { return }
                $obj = [ordered]@{
                    AccountName       = $_.SamAccountName
                    FirstName         = $_.GivenName
                    LastName          = $_.Sn
                    Email             = $(if ($IncludeEmail) { $_.mail } else { "" })
                    DisplayName       = $_.DisplayName
                    UserPrincipalName = $_.UserPrincipalName
                    Enabled           = $_.Enabled
                }
                foreach ($attr in $extra) {
                    try { $obj[$attr] = $_.$attr } catch { $obj[$attr] = $null }
                }
                if ($_.Manager) {
                    $mgr = Resolve-ManagerInfo -ManagerDN $_.Manager
                    $obj['ManagerDN'] = $mgr.ManagerDN
                    $obj['ManagerDisplayName'] = $mgr.ManagerDisplayName
                    $obj['ManagerAccountName'] = $mgr.ManagerAccountName
                    $obj['ManagerUPN'] = $mgr.ManagerUPN
                    $obj['ManagerCanonicalName'] = $mgr.ManagerCanonicalName
                }
                [PSCustomObject]$obj
            }
            if ($pgusers) { $report += $pgusers }
        }
    }
    catch { }
}

# Distinct
$report = $report | Sort-Object AccountName -Unique

# Guardar en servidor (opcional)
$serverSavedPath = $null
if ($SaveToServer -and -not [string]::IsNullOrWhiteSpace($OutFolder)) {
    try {
        if (-not (Test-Path -LiteralPath $OutFolder)) {
            New-Item -Path $OutFolder -ItemType Directory -Force | Out-Null
        }
        $ts = Get-Date -Format yyyyMMdd_HHmmss
        $safeGroup = ($sanitizedGroup -replace '[^\w\.\-]', '_')
        $baseName = "GroupLookup_{0}_{1}" -f $safeGroup, $ts
        if ($Format -eq 'json') {
            $serverSavedPath = Join-Path $OutFolder ($baseName + '.json')
            $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $serverSavedPath -Encoding utf8
        }
        else {
            $serverSavedPath = Join-Path $OutFolder ($baseName + '.csv')
            $report | Export-Csv -Path $serverSavedPath -NoTypeInformation -Encoding utf8
        }
    }
    catch { }
}

# Responder
try {
    $ctx = [System.Web.HttpContext]::Current
    if ($serverSavedPath) { Set-ResponseHeader -Name 'X-Saved-Path' -Value $serverSavedPath }

    if ($Format -eq 'json') {
        if ($ctx) { $ctx.Response.ContentType = "application/json; charset=utf-8" }
        $json = $report | ConvertTo-Json -Depth 6
        Write-ResponseText $json
    }
    else {
        $ts = Get-Date -Format yyyyMMdd_HHmmss
        $fileName = "GroupLookup_{0}_{1}.csv" -f ($sanitizedGroup -replace '[^\w\.\-]', '_'), $ts
        if ($ctx) {
            $ctx.Response.ContentType = "text/csv; charset=utf-8"
            $ctx.Response.AddHeader("Content-Disposition", "attachment; filename=""$fileName""")
        }
        $csvLines = $report | ConvertTo-Csv -NoTypeInformation
        $csvText = ($csvLines -join "`r`n") + "`r`n"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($csvText)
        Write-ResponseBytes $bytes
    }
}
catch {
    try { if ($ctx) { $ctx.Response.StatusCode = 500 } } catch {}
    Write-ResponseText "Unexpected server error."
}