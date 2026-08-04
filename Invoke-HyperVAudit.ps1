<#
.SYNOPSIS
    KYTHEL Hyper-V Audit — a read-only best-practices report for Hyper-V hosts.

.DESCRIPTION
    Inventories every VM on a Hyper-V host (or cluster node) and checks the
    configuration against Microsoft best practices:

      * Memory  : dynamic vs static allocation, overcommit vs host RAM
      * CPU     : vCPU:pCPU oversubscription ratio
      * Storage : VHD (legacy) vs VHDX, dynamic disks near-full volumes,
                  VMs stored on the OS drive, host volume free space
      * Hygiene : lingering checkpoints, missing integration services,
                  Generation 1 VMs, automatic start/stop actions
      * Network : VMQ enabled on 1GbE adapters (known performance issue),
                  virtual switch inventory
      * Domain controllers (heuristic, by VM name): checkpoints on DCs,
                  dynamic memory on DCs, two DCs on the same host
      * Cluster (when the node is clustered): CSV free space, quorum witness,
                  Cluster-Aware Updating role, DC anti-affinity classes

    The script is STRICTLY READ-ONLY. It contains no Set-*, no Enable-*, no
    Remove-* calls against your infrastructure — safe to run on production
    hosts during business hours. It changes nothing; it only reports.

    Output: a color-coded console summary and a self-contained HTML report.
    Optional JSON export for automation.

.PARAMETER OutputPath
    Where to write the HTML report.
    Default: .\HyperV-Audit-<hostname>-<date>.html

.PARAMETER DomainControllerPattern
    Regex matched against VM names to identify probable domain controllers
    for the DC-specific checks. Default: 'DC|DOMAIN|ADDS'

.PARAMETER Json
    Also write the findings and inventory as JSON next to the HTML report.

.EXAMPLE
    PS> .\Invoke-HyperVAudit.ps1
    Audits the local host, writes the HTML report to the current folder.

.EXAMPLE
    PS> .\Invoke-HyperVAudit.ps1 -OutputPath C:\Reports\audit.html -Json

.NOTES
    Author  : Laz @ KYTHEL — https://kythel.com
    License : MIT
    Requires: Windows Server 2016+ / Windows 10+ with the Hyper-V role and
              PowerShell 5.1+. Run from an elevated (Administrator) session —
              Get-VHD needs it.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$DomainControllerPattern = 'DC|DOMAIN|ADDS',
    [switch]$Json
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- guards
if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    Write-Error ("The Hyper-V PowerShell module is not installed. " +
        "Install the Hyper-V management tools and re-run. Nothing was changed.")
    return
}
Import-Module Hyper-V

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning ("Not running elevated. VM inventory will work, but disk details " +
        "(Get-VHD) will be skipped. For the full report, run as Administrator.")
}

$hostName = $env:COMPUTERNAME
$stamp    = Get-Date -Format 'yyyy-MM-dd_HHmm'
if (-not $OutputPath) { $OutputPath = ".\HyperV-Audit-$hostName-$stamp.html" }

# ---------------------------------------------------------------- findings
$findings = New-Object System.Collections.Generic.List[object]
$sevRank  = @{ CRITICAL = 0; WARNING = 1; INFO = 2; OK = 3 }

function Add-Finding {
    param(
        [ValidateSet('CRITICAL','WARNING','INFO','OK')][string]$Severity,
        [string]$Category,
        [string]$Target,
        [string]$Message,
        [string]$Recommendation = ''
    )
    $findings.Add([pscustomobject]@{
        Severity       = $Severity
        Category       = $Category
        Target         = $Target
        Message        = $Message
        Recommendation = $Recommendation
    })
}

Write-Host ''
Write-Host '  KYTHEL Hyper-V Audit' -ForegroundColor Cyan
Write-Host "  Host: $hostName  ·  $(Get-Date -Format 'yyyy-MM-dd HH:mm')  ·  read-only" -ForegroundColor DarkGray
Write-Host ''

# ---------------------------------------------------------------- host facts
Write-Host '  [1/6] Host…' -ForegroundColor DarkGray
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$vmHost = Get-VMHost

$hostRamGB   = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
$freeRamGB   = [math]::Round($os.FreePhysicalMemory * 1KB / 1GB, 1)
$logicalCpus = ([int]$cs.NumberOfLogicalProcessors)
$uptimeDays  = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)

$lastPatch = $null
try { $lastPatch = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn } catch {}
if ($lastPatch -and $lastPatch -lt (Get-Date).AddDays(-60)) {
    Add-Finding -Severity WARNING -Category 'Host' -Target $hostName `
        -Message "Last Windows update installed $($lastPatch.ToString('yyyy-MM-dd')) — more than 60 days ago." `
        -Recommendation 'Patch the host on a maintenance window. Unpatched hypervisors put every VM at risk.'
}
if ($uptimeDays -gt 90) {
    Add-Finding -Severity INFO -Category 'Host' -Target $hostName `
        -Message "Host uptime is $uptimeDays days." `
        -Recommendation 'Long uptime usually means missed patch reboots. Verify patching actually completes.'
}

# Host volumes
$volumes = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
foreach ($vol in $volumes) {
    if ($vol.Size -eq $null -or $vol.Size -eq 0) { continue }
    $freePct = [math]::Round(100 * $vol.FreeSpace / $vol.Size, 1)
    if ($freePct -lt 10) {
        Add-Finding -Severity CRITICAL -Category 'Storage' -Target "$hostName $($vol.DeviceID)" `
            -Message "Volume $($vol.DeviceID) has only $freePct% free ($([math]::Round($vol.FreeSpace/1GB,1)) GB)." `
            -Recommendation 'Below 10% free, dynamically expanding VHDX files can fail to grow and PAUSE their VMs. Free space or extend the volume now.'
    }
    elseif ($freePct -lt 20) {
        Add-Finding -Severity WARNING -Category 'Storage' -Target "$hostName $($vol.DeviceID)" `
            -Message "Volume $($vol.DeviceID) is at $freePct% free." `
            -Recommendation 'Keep 20%+ free on volumes that hold growing virtual disks.'
    }
}

# ---------------------------------------------------------------- VM inventory
Write-Host '  [2/6] Virtual machines…' -ForegroundColor DarkGray
$vms = @(Get-VM)
if ($vms.Count -eq 0) {
    Write-Host '  No VMs found on this host. Nothing to audit.' -ForegroundColor Yellow
    return
}

$inventory     = New-Object System.Collections.Generic.List[object]
$totalVcpu     = 0
$staticRamGB   = 0.0
$maxDynRamGB   = 0.0
$runningCount  = 0
$systemDrive   = $env:SystemDrive

foreach ($vm in $vms) {
    $mem  = Get-VMMemory    -VMName $vm.Name
    $cpu  = Get-VMProcessor -VMName $vm.Name
    $isRunning = $vm.State -eq 'Running'
    if ($isRunning) { $runningCount++; $totalVcpu += [int]$cpu.Count }

    # ---- memory model
    $memGB = [math]::Round($mem.Startup / 1GB, 1)
    if ($mem.DynamicMemoryEnabled) {
        $memText = "Dynamic $([math]::Round($mem.Minimum/1GB,1))–$([math]::Round($mem.Maximum/1GB,1)) GB"
        if ($isRunning) { $maxDynRamGB += $mem.Maximum / 1GB }
    } else {
        $memText = "Static $memGB GB"
        if ($isRunning) { $staticRamGB += $mem.Startup / 1GB }
    }

    $isDC = $vm.Name -match $DomainControllerPattern

    if (-not $mem.DynamicMemoryEnabled -and -not $isDC) {
        Add-Finding -Severity INFO -Category 'Memory' -Target $vm.Name `
            -Message "Uses static memory ($memGB GB)." `
            -Recommendation ('General-purpose VMs usually benefit from dynamic memory so the host can balance RAM. ' +
                'Keep static only for workloads that manage their own memory (SQL Server, Exchange) or where a vendor requires it.')
    }
    if ($mem.DynamicMemoryEnabled -and $isDC) {
        Add-Finding -Severity WARNING -Category 'Domain controller' -Target $vm.Name `
            -Message 'Probable domain controller is using dynamic memory.' `
            -Recommendation 'Microsoft recommends fixed memory for DCs — the AD database cache does not cooperate with ballooning.'
    }

    # ---- checkpoints
    $checkpoints = @(Get-VMSnapshot -VMName $vm.Name -ErrorAction SilentlyContinue)
    $oldCheckpoints = @($checkpoints | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-7) })
    if ($isDC -and $checkpoints.Count -gt 0) {
        Add-Finding -Severity CRITICAL -Category 'Domain controller' -Target $vm.Name `
            -Message "Probable domain controller has $($checkpoints.Count) checkpoint(s)." `
            -Recommendation 'Never keep checkpoints on DCs — applying an old one can cause USN rollback and break replication domain-wide. Remove them (merges automatically).'
    }
    elseif ($oldCheckpoints.Count -gt 0) {
        $oldest = ($checkpoints | Sort-Object CreationTime | Select-Object -First 1).CreationTime
        Add-Finding -Severity WARNING -Category 'Checkpoints' -Target $vm.Name `
            -Message "$($oldCheckpoints.Count) checkpoint(s) older than 7 days (oldest: $($oldest.ToString('yyyy-MM-dd')))." `
            -Recommendation 'Old checkpoints grow AVHDX chains, eat disk, and slow I/O. Checkpoints are not backups — delete after the change they covered is confirmed good.'
    }

    # ---- generation & integration services
    if ($vm.Generation -eq 1) {
        Add-Finding -Severity INFO -Category 'Configuration' -Target $vm.Name `
            -Message 'Generation 1 VM.' `
            -Recommendation 'Fine for legacy OSes; new VMs should be Generation 2 (UEFI, Secure Boot, better performance).'
    }
    $ic = @(Get-VMIntegrationService -VMName $vm.Name -ErrorAction SilentlyContinue)
    $icOff = @($ic | Where-Object { -not $_.Enabled -and $_.Name -in @('Heartbeat','Key-Value Pair Exchange','VSS') })
    foreach ($svc in $icOff) {
        Add-Finding -Severity WARNING -Category 'Integration services' -Target $vm.Name `
            -Message "Integration service disabled: $($svc.Name)." `
            -Recommendation 'Heartbeat, KVP, and VSS should stay enabled — monitoring and consistent backups depend on them.'
    }
    if ($isDC) {
        $timeSync = $ic | Where-Object { $_.Name -eq 'Time Synchronization' -and $_.Enabled }
        if ($timeSync) {
            Add-Finding -Severity INFO -Category 'Domain controller' -Target $vm.Name `
                -Message 'Time Synchronization integration service is enabled on a probable DC.' `
                -Recommendation 'The PDC emulator should take time from a reliable NTP source, not the host. Review your domain time hierarchy.'
        }
    }

    # ---- automatic actions
    if ($vm.AutomaticStopAction -eq 'TurnOff') {
        Add-Finding -Severity WARNING -Category 'Configuration' -Target $vm.Name `
            -Message 'Automatic stop action is "TurnOff" (hard power-off on host shutdown).' `
            -Recommendation 'Use "Save" or "ShutDown" — TurnOff is pulling the plug and risks guest corruption.'
    }

    # ---- disks
    $diskSummaries = @()
    $disks = @(Get-VMHardDiskDrive -VMName $vm.Name)
    foreach ($d in $disks) {
        if (-not $d.Path) { continue }
        if ($d.Path -like "$systemDrive\*") {
            Add-Finding -Severity WARNING -Category 'Storage' -Target $vm.Name `
                -Message "Virtual disk lives on the host OS drive: $($d.Path)" `
                -Recommendation 'Keep VM storage off the system volume — a disk that fills pauses VMs AND cripples the host itself.'
        }
        if ([IO.Path]::GetExtension($d.Path) -ieq '.vhd') {
            Add-Finding -Severity WARNING -Category 'Storage' -Target $vm.Name `
                -Message "Legacy VHD format disk: $(Split-Path $d.Path -Leaf)" `
                -Recommendation 'Convert to VHDX (2 TB+ support, corruption resilience, better performance). Convert-VHD does it offline.'
        }
        if ($isAdmin) {
            try {
                $vhd = Get-VHD -Path $d.Path
                $sizeGB = [math]::Round($vhd.Size / 1GB, 1)
                $fileGB = [math]::Round($vhd.FileSize / 1GB, 1)
                $diskSummaries += "$(Split-Path $d.Path -Leaf) ($($vhd.VhdType), $fileGB/$sizeGB GB)"
            } catch {
                $diskSummaries += (Split-Path $d.Path -Leaf)
            }
        } else {
            $diskSummaries += (Split-Path $d.Path -Leaf)
        }
    }

    $inventory.Add([pscustomobject]@{
        Name        = $vm.Name
        State       = [string]$vm.State
        Generation  = $vm.Generation
        vCPU        = [int]$cpu.Count
        Memory      = $memText
        MemDemand   = if ($isRunning -and $mem.DynamicMemoryEnabled) { "$([math]::Round($vm.MemoryDemand/1GB,1)) GB" } else { '—' }
        Checkpoints = $checkpoints.Count
        Disks       = ($diskSummaries -join '; ')
        Uptime      = if ($isRunning) { "$([math]::Round($vm.Uptime.TotalDays,1))d" } else { '—' }
        ProbableDC  = $isDC
    })
}

# ---------------------------------------------------------------- capacity math
Write-Host '  [3/6] Capacity…' -ForegroundColor DarkGray
if ($logicalCpus -gt 0 -and $totalVcpu -gt 0) {
    $ratio = [math]::Round($totalVcpu / $logicalCpus, 1)
    if ($ratio -gt 8) {
        Add-Finding -Severity CRITICAL -Category 'CPU' -Target $hostName `
            -Message "vCPU oversubscription is ${ratio}:1 ($totalVcpu vCPU on $logicalCpus logical processors)." `
            -Recommendation 'Above 8:1 even light workloads contend. Reduce vCPU counts (most VMs run fine with 2) or add host capacity.'
    }
    elseif ($ratio -gt 4) {
        Add-Finding -Severity WARNING -Category 'CPU' -Target $hostName `
            -Message "vCPU oversubscription is ${ratio}:1." `
            -Recommendation 'Fine for light workloads; watch CPU Wait Time Per Dispatch if users report sluggishness.'
    } else {
        Add-Finding -Severity OK -Category 'CPU' -Target $hostName `
            -Message "vCPU oversubscription is ${ratio}:1 — healthy."
    }
}

$committedGB = [math]::Round($staticRamGB + $maxDynRamGB, 1)
if ($committedGB -gt ($hostRamGB * 1.25)) {
    Add-Finding -Severity WARNING -Category 'Memory' -Target $hostName `
        -Message "Worst-case VM memory ($committedGB GB: static + dynamic maximums) exceeds host RAM ($hostRamGB GB) by more than 25%." `
        -Recommendation 'If every dynamic VM balloons to its maximum at once, the host will swap. Lower dynamic maximums to realistic ceilings.'
} elseif ($committedGB -gt $hostRamGB) {
    Add-Finding -Severity INFO -Category 'Memory' -Target $hostName `
        -Message "Worst-case VM memory ($committedGB GB) slightly exceeds host RAM ($hostRamGB GB)." `
        -Recommendation 'Acceptable with dynamic memory, but keep an eye on it as VMs are added.'
}

# ---------------------------------------------------------------- DC affinity (single host)
$dcVMs = @($inventory | Where-Object { $_.ProbableDC })
if ($dcVMs.Count -ge 2) {
    Add-Finding -Severity WARNING -Category 'Domain controller' -Target ($dcVMs.Name -join ', ') `
        -Message "$($dcVMs.Count) probable domain controllers run on this same host." `
        -Recommendation 'One host failure takes down all of them. Keep at least one DC on separate hardware (or a physical box), and use anti-affinity in clusters.'
}

# ---------------------------------------------------------------- network
Write-Host '  [4/6] Network…' -ForegroundColor DarkGray
try {
    $slowVmqAdapters = @(Get-NetAdapter -Physical -ErrorAction Stop |
        Where-Object { $_.Status -eq 'Up' -and $_.LinkSpeed -match '^1 Gbps' })
    foreach ($nic in $slowVmqAdapters) {
        $vmq = Get-NetAdapterVmq -Name $nic.Name -ErrorAction SilentlyContinue
        if ($vmq -and $vmq.Enabled) {
            Add-Finding -Severity WARNING -Category 'Network' -Target $nic.Name `
                -Message "VMQ is enabled on a 1 GbE adapter ($($nic.InterfaceDescription))." `
                -Recommendation 'VMQ on 1GbE NICs (notoriously certain Broadcom models) causes VM network slowness and packet loss. On 1GbE, disable VMQ; it only pays off at 10 GbE+.'
        }
    }
} catch {
    Add-Finding -Severity INFO -Category 'Network' -Target $hostName `
        -Message 'Could not query physical adapters for the VMQ check.' -Recommendation ''
}
$switches = @(Get-VMSwitch -ErrorAction SilentlyContinue)

# ---------------------------------------------------------------- cluster
Write-Host '  [5/6] Cluster…' -ForegroundColor DarkGray
$clusterName = $null
if (Get-Module -ListAvailable -Name FailoverClusters) {
    try {
        Import-Module FailoverClusters -ErrorAction Stop
        $cluster = Get-Cluster -ErrorAction Stop
        $clusterName = $cluster.Name

        # CSV space
        foreach ($csv in @(Get-ClusterSharedVolume -ErrorAction SilentlyContinue)) {
            foreach ($pi in $csv.SharedVolumeInfo) {
                $freePct = [math]::Round(100 * $pi.Partition.FreeSpace / $pi.Partition.Size, 1)
                if ($freePct -lt 15) {
                    Add-Finding -Severity CRITICAL -Category 'Cluster' -Target $csv.Name `
                        -Message "Cluster Shared Volume at $freePct% free." `
                        -Recommendation 'CSVs need headroom for disk growth, checkpoints, and live migration. Extend or clean up now.'
                }
            }
        }

        # witness / quorum
        $quorum = Get-ClusterQuorum -ErrorAction SilentlyContinue
        if ($quorum -and -not $quorum.QuorumResource -and @(Get-ClusterNode).Count % 2 -eq 0) {
            Add-Finding -Severity WARNING -Category 'Cluster' -Target $clusterName `
                -Message 'Even node count with no quorum witness configured.' `
                -Recommendation 'Configure a file share or cloud witness — without one, losing half the nodes stops the whole cluster.'
        }

        # Cluster-Aware Updating
        $cauRole = $null
        try { $cauRole = Get-CauClusterRole -ErrorAction Stop } catch {}
        if (-not $cauRole) {
            Add-Finding -Severity INFO -Category 'Cluster' -Target $clusterName `
                -Message 'Cluster-Aware Updating (CAU) role not detected.' `
                -Recommendation 'CAU patches nodes one at a time with automatic drain and failback — patching stops being a weekend project. Worth enabling.'
        } else {
            Add-Finding -Severity OK -Category 'Cluster' -Target $clusterName `
                -Message 'Cluster-Aware Updating role is configured.'
        }

        # DC anti-affinity
        $dcGroups = @(Get-ClusterGroup | Where-Object { $_.Name -match $DomainControllerPattern })
        $noAffinity = @($dcGroups | Where-Object { -not $_.AntiAffinityClassNames })
        if ($dcGroups.Count -ge 2 -and $noAffinity.Count -gt 0) {
            Add-Finding -Severity WARNING -Category 'Cluster' -Target ($dcGroups.Name -join ', ') `
                -Message 'Clustered probable-DC roles have no AntiAffinityClassNames set.' `
                -Recommendation 'Set the same anti-affinity class on all DC roles so the cluster never lands them on one node: (Get-ClusterGroup "DC-VM").AntiAffinityClassNames = "DomainControllers"'
        }
    } catch {
        # not clustered — nothing to check
    }
}

# ---------------------------------------------------------------- summary + report
Write-Host '  [6/6] Report…' -ForegroundColor DarkGray

$sorted = $findings | Sort-Object { $sevRank[$_.Severity] }, Category
$counts = @{ CRITICAL = 0; WARNING = 0; INFO = 0; OK = 0 }
foreach ($f in $findings) { $counts[$f.Severity]++ }

Write-Host ''
Write-Host ("  {0} VMs ({1} running) · {2} vCPU on {3} LPs · {4} GB RAM ({5} GB free)" -f `
    $vms.Count, $runningCount, $totalVcpu, $logicalCpus, $hostRamGB, $freeRamGB)
Write-Host ("  Findings: {0} critical · {1} warning · {2} info · {3} ok" -f `
    $counts.CRITICAL, $counts.WARNING, $counts.INFO, $counts.OK)
Write-Host ''
foreach ($f in $sorted) {
    $color = switch ($f.Severity) {
        'CRITICAL' { 'Red' } 'WARNING' { 'Yellow' } 'INFO' { 'Cyan' } default { 'Green' }
    }
    Write-Host ("  [{0}] {1} — {2}" -f $f.Severity, $f.Target, $f.Message) -ForegroundColor $color
}

# ---- HTML
$sevColor = @{ CRITICAL = '#c0392b'; WARNING = '#b07a00'; INFO = '#3378ff'; OK = '#3d7a00' }
$enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

$rowsFindings = ($sorted | ForEach-Object {
    $c = $sevColor[$_.Severity]
    '<tr><td><span class="sev" style="background:{0}">{1}</span></td><td>{2}</td><td>{3}</td><td>{4}<div class="rec">{5}</div></td></tr>' -f `
        $c, $_.Severity, (& $enc $_.Category), (& $enc $_.Target), (& $enc $_.Message), (& $enc $_.Recommendation)
}) -join "`n"

$rowsVms = ($inventory | ForEach-Object {
    '<tr><td>{0}{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td></tr>' -f `
        (& $enc $_.Name), $(if ($_.ProbableDC) { ' <span class="dc">DC?</span>' } else { '' }),
        $_.State, $_.Generation, $_.vCPU, (& $enc $_.Memory), $_.MemDemand, $_.Checkpoints, (& $enc $_.Disks)
}) -join "`n"

$switchList = if ($switches.Count) {
    (& $enc (($switches | ForEach-Object { "$($_.Name) ($($_.SwitchType))" }) -join ', '))
} else { 'none found' }
$clusterLine = if ($clusterName) { "Cluster: $(& $enc $clusterName)" } else { 'Standalone host (not clustered)' }

$html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hyper-V Audit — $(& $enc $hostName) — $stamp</title>
<style>
 body{font-family:"Segoe UI",system-ui,sans-serif;margin:0;background:#f7f7f4;color:#1e1f36}
 header{background:#1e1f36;color:#fff;padding:20px 28px}
 header h1{margin:0;font-size:19px} header h1 b{color:#b5ff1b}
 header p{margin:4px 0 0;color:#ffffff99;font-size:13px}
 main{max-width:1080px;margin:0 auto;padding:24px 28px 60px}
 .stats{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
 .stat{background:#fff;border:1px solid #e3e3ea;border-radius:10px;padding:10px 18px;font-size:13px}
 .stat b{display:block;font-size:20px}
 h2{font-size:16px;margin:28px 0 8px}
 table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e3e3ea;font-size:13px}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top}
 th{background:#f0f0ee;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
 .sev{color:#fff;font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:999px;white-space:nowrap}
 .rec{color:#6a6d85;font-size:12px;margin-top:3px}
 .dc{background:#fdf3dd;color:#b07a00;font-size:10px;font-weight:700;padding:1px 6px;border-radius:999px}
 footer{margin-top:36px;font-size:12px;color:#6a6d85}
 footer a{color:#3378ff}
</style></head><body>
<header>
 <h1><b>KYTHEL</b> · Hyper-V Audit</h1>
 <p>Host $(& $enc $hostName) · $(Get-Date -Format 'yyyy-MM-dd HH:mm') · $clusterLine · read-only audit, no changes made</p>
</header>
<main>
 <div class="stats">
  <div class="stat"><b>$($vms.Count)</b>VMs ($runningCount running)</div>
  <div class="stat"><b>$totalVcpu / $logicalCpus</b>vCPU / logical CPUs</div>
  <div class="stat"><b>$hostRamGB GB</b>host RAM ($freeRamGB free)</div>
  <div class="stat"><b style="color:#c0392b">$($counts.CRITICAL)</b>critical</div>
  <div class="stat"><b style="color:#b07a00">$($counts.WARNING)</b>warnings</div>
  <div class="stat"><b style="color:#3378ff">$($counts.INFO)</b>info</div>
 </div>
 <h2>Findings</h2>
 <table><thead><tr><th>Severity</th><th>Category</th><th>Target</th><th>Finding &amp; recommendation</th></tr></thead>
 <tbody>$rowsFindings</tbody></table>
 <h2>VM inventory</h2>
 <table><thead><tr><th>VM</th><th>State</th><th>Gen</th><th>vCPU</th><th>Memory</th><th>Demand</th><th>Ckpts</th><th>Disks</th></tr></thead>
 <tbody>$rowsVms</tbody></table>
 <h2>Virtual switches</h2>
 <p style="font-size:13px">$switchList</p>
 <footer>
  Generated by <a href="https://github.com/kythel/hyperv-audit">KYTHEL Hyper-V Audit</a> —
  free and open source, MIT license. Built by
  <a href="https://kythel.com">KYTHEL</a>, managed IT services in Boynton Beach, FL.
  This audit is read-only: it reports, it never changes your configuration.
 </footer>
</main></body></html>
"@

$html | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host ''
Write-Host "  HTML report: $OutputPath" -ForegroundColor Green

if ($Json) {
    $jsonPath = [IO.Path]::ChangeExtension($OutputPath, 'json')
    [pscustomobject]@{
        Host      = $hostName
        Generated = (Get-Date -Format 'o')
        Cluster   = $clusterName
        Summary   = $counts
        Findings  = $sorted
        Inventory = $inventory
    } | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding utf8
    Write-Host "  JSON export: $jsonPath" -ForegroundColor Green
}
Write-Host ''
