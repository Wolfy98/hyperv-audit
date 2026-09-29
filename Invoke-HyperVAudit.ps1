<#
================================================================================
  Invoke-HyperVAudit.ps1·  v2.0
  Hyper-V / Failover-Cluster inventory & health assessment  --  READ ONLY
  ================================================================================

  WHAT IT DOES
    Maps a Hyper-V host (or an entire failover cluster) end to end: hosts,
    roles, quorum, storage/SAN, MPIO, CSVs, networking, live migration, every
    VM's CPU/RAM/disk (provisioned vs actual), checkpoints, integration
    services and cluster priority. It checks host stability & patch recency
    (uptime, pending reboot, newest update, firmware), live per-VM utilization
    (CPU% and memory demand vs assigned), VM security posture (Secure Boot /
    vTPM), platform currency (config version & guest tools), Hyper-V Replica
    health, network hardware acceleration (VMQ/RSS/SR-IOV), Cluster-Aware
    Updating, an N+1 failover-capacity check, and domain-controller safety
    (checkpoints on DCs, dynamic memory on DCs, DCs sharing a host,
    anti-affinity in clusters).

    v2.0 adds a self-contained HTML report: every finding is explained in
    three parts â€” WHAT WE SAW, WHY IT MATTERS, WHAT TO DO â€” so the report
    reads like an engineer's write-up, not a wall of raw data.

  SAFETY  --  THIS SCRIPT DOES NOT CHANGE ANYTHING
    Read verbs only (Get-*), plus 'mpclaim -s' and 'iscsicli
    ListPersistentTargets' (both status displays) and an optional transcript
    file. There is no Set / New-VM / Remove / Move / Enable against your
    infrastructure anywhere in it. Safe to run against production during
    business hours.

  HOW TO RUN
    1. Open PowerShell as Administrator on the Hyper-V host.
    2. If needed:  Set-ExecutionPolicy -Scope Process Bypass
    3. .\Invoke-HyperVAudit.ps1
       (optional)  .\Invoke-HyperVAudit.ps1 -OutputFolder D:\Reports -Json

  OUTPUT
    <OutputFolder>\HyperVAudit_<HOST>_<yyyyMMdd-HHmm>.html   (the report)
    <OutputFolder>\HyperVAudit_<HOST>_<yyyyMMdd-HHmm>.txt    (console transcript)
    <OutputFolder>\HyperVAudit_<HOST>_<yyyyMMdd-HHmm>.json   (with -Json)

  It auto-detects standalone vs clustered. On a standalone host the cluster
  sections are skipped automatically.
================================================================================
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$OutputFolder = [Environment]::GetFolderPath('Desktop'),
    [string]$DomainControllerPattern = 'DC|DOMAIN|ADDS',
    [int]$MemoryReserveGB   = 16,   # host RAM held back per node for the OS in the N+1 check
    [int]$CheckpointAgeDays = 7,    # checkpoints older than this are flagged as bloat
    [int]$MaxUptimeDays     = 45,   # host uptime beyond this is flagged (likely missed patch cycle)
    [int]$MaxPatchAgeDays   = 45,   # newest installed update older than this is flagged
    [switch]$Json,
    [switch]$NoTranscript
)

# ------------------------------------------------------------------ setup ---
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
if (-not (Test-Path $OutputFolder)) { $OutputFolder = [Environment]::GetFolderPath('Desktop') }
$baseName = "HyperVAudit_{0}_{1}" -f $env:COMPUTERNAME, $stamp
$logFile  = Join-Path $OutputFolder "$baseName.txt"
$htmlFile = Join-Path $OutputFolder "$baseName.html"
if (-not $NoTranscript) { Start-Transcript -Path $logFile -Force | Out-Null }

$Flags = New-Object System.Collections.Generic.List[object]
function Add-Flag {
    param(
        [ValidateSet('HIGH','MEDIUM','LOW','INFO','OK')][string]$Sev,
        [string]$Target,
        [string]$Msg,          # WHAT WE SAW
        [string]$Why  = '',    # WHY IT MATTERS
        [string]$Fix  = ''     # WHAT TO DO
    )
    $Flags.Add([pscustomobject]@{ Severity=$Sev; Target=$Target; Message=$Msg; Why=$Why; Fix=$Fix })
}
function Section { param([string]$Title)
    Write-Host ""
    Write-Host ("================ {0} ================" -f $Title) -ForegroundColor Cyan }
function Safe { param([scriptblock]$Block,[string]$Label)
    try { & $Block } catch { Write-Host ("  [skip] {0}: {1}" -f $Label, $_.Exception.Message) -ForegroundColor DarkYellow } }

Write-Host ("BW Hyper-V Audit v2.0  |  Host: {0}  |  {1}" -f $env:COMPUTERNAME, (Get-Date)) -ForegroundColor Green
Write-Host  "READ-ONLY: this script inspects only; it changes nothing." -ForegroundColor Green
if (-not $NoTranscript) { Write-Host ("Transcript: {0}" -f $logFile) -ForegroundColor DarkGray }

# ------------------------------------------------------- identity & OS ---
Section "IDENTITY & OS"
Safe { Get-CimInstance Win32_OperatingSystem | Select-Object CSName,Caption,Version,BuildNumber,OSArchitecture | Format-List } "OS"
$cs = $null
Safe {
    $script:cs = Get-CimInstance Win32_ComputerSystem
    $cs | Select-Object Domain,Manufacturer,Model,
        @{n='TotalRAM_GB';e={[math]::Round($_.TotalPhysicalMemory/1GB,2)}},
        NumberOfProcessors,NumberOfLogicalProcessors | Format-List
} "ComputerSystem"

# ---- host stability, patch recency, firmware, pending reboot (THIS node) ----
Section "HOST STABILITY & PATCHING (this node)"
Safe {
    $os   = Get-CimInstance Win32_OperatingSystem
    $up   = (Get-Date) - $os.LastBootUpTime
    $bios = Get-CimInstance Win32_BIOS
    $lastHfx = Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $pending = @()   # all read-only registry reads
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'CBS' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'WindowsUpdate' }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA SilentlyContinue).PendingFileRenameOperations) { $pending += 'FileRename' }
    [pscustomobject]@{
        LastBoot      = $os.LastBootUpTime
        UptimeDays    = [math]::Round($up.TotalDays,1)
        NewestUpdate  = if ($lastHfx -and $lastHfx.InstalledOn) { "$($lastHfx.HotFixID) ($($lastHfx.InstalledOn.ToString('yyyy-MM-dd')))" } else { 'none reported' }
        Firmware      = $bios.SMBIOSBIOSVersion
        PendingReboot = if ($pending) { $pending -join ', ' } else { 'No' }
    } | Format-List
    if ($up.TotalDays -gt $MaxUptimeDays) {
        Add-Flag MEDIUM $env:COMPUTERNAME "Host uptime $([math]::Round($up.TotalDays,0)) days (> $MaxUptimeDays)." `
            -Why "Hypervisors that stay up past a monthly patch cycle usually mean updates are not completing. An unpatched host is a security and stability risk for every VM on it." `
            -Fix "Verify patching actually runs to completion, and schedule the reboot in a maintenance window."
    }
    if ($pending) {
        Add-Flag MEDIUM $env:COMPUTERNAME "Pending reboot detected ($($pending -join ', '))." `
            -Why "Updates are only partially applied until the reboot happens - the host is running in a half-patched state that Microsoft does not test." `
            -Fix "Schedule the reboot. In a cluster, drain the node first (pause + move roles), reboot, resume."
    }
    if ($lastHfx -and $lastHfx.InstalledOn -and ((Get-Date) - $lastHfx.InstalledOn).TotalDays -gt $MaxPatchAgeDays) {
        Add-Flag MEDIUM $env:COMPUTERNAME "Newest update is $([math]::Round(((Get-Date)-$lastHfx.InstalledOn).TotalDays,0)) days old (> $MaxPatchAgeDays)." `
            -Why "Hyper-V hosts are a high-value target: one compromised host means every VM on it is compromised." `
            -Fix "Review why updates stopped (broken WSUS target, disabled service, failed installs) and bring the host current."
    }
} "HostStability"

# ----------------------------------------------------------- features ---
Section "ROLES / FEATURES"
Safe { Get-WindowsFeature Hyper-V,Failover-Clustering,FS-FileServer,Multipath-IO -EA Stop |
        Select-Object Name,InstallState | Format-Table -AutoSize } "Features"

# --------------------------------------------------- cluster detection ---
Section "CLUSTER DETECTION"
$isCluster = $false; $nodes = @($env:COMPUTERNAME)
$cluster = try { Get-Cluster -EA Stop } catch { $null }
if ($cluster) {
    $isCluster = $true
    $cluster | Select-Object Name,Domain,
        @{n='S2D';e={if($_.S2DEnabled){'Enabled'}else{'Disabled'}}} | Format-List
    Safe {
        $cn = Get-ClusterNode
        $cn | Select-Object Name,State,NodeWeight | Format-Table -AutoSize
        # $script: is required - a plain assignment inside this scriptblock would
        # create a local copy and the cluster-wide loops would silently audit
        # only the launching node (latent bug found by PSScriptAnalyzer).
        $script:nodes = @(($cn | Where-Object State -eq 'Up').Name)
        foreach ($n in ($cn | Where-Object State -ne 'Up')) {
            Add-Flag HIGH $n.Name "Cluster node is $($n.State) (not Up)." `
                -Why "A down node means reduced failover capacity right now - and if it went down unnoticed, monitoring has a gap." `
                -Fix "Investigate why the node is down and restore it, or evict it deliberately if it is being retired."
        }
    } "ClusterNode"
    Safe { Write-Host "Quorum:" -ForegroundColor Yellow
           Get-ClusterQuorum | Select-Object QuorumResource,QuorumType | Format-List } "Quorum"
    Safe {
        $q = Get-ClusterQuorum -EA SilentlyContinue
        if ($q -and -not $q.QuorumResource -and (@(Get-ClusterNode).Count % 2 -eq 0)) {
            Add-Flag MEDIUM $cluster.Name "Even node count with no quorum witness configured." `
                -Why "Without a witness, losing exactly half the nodes stops the WHOLE cluster - including the healthy half." `
                -Fix "Configure a cloud witness (cheapest) or file-share witness: Set-ClusterQuorum -CloudWitness (run by a human, in a change window)."
        }
    } "QuorumWitness"
} else {
    Write-Host "Standalone host (no failover cluster). Cluster-wide checks skipped." -ForegroundColor Yellow
}

# ---- cluster patching posture: Cluster-Aware Updating (CAU) ----
if ($isCluster) {
    Section "CLUSTER - PATCHING (Cluster-Aware Updating)"
    Safe {
        $cau = Get-CauClusterRole -ClusterName $cluster.Name -EA SilentlyContinue
        if ($cau) { $cau | Format-Table -AutoSize | Out-Host }
        else {
            Write-Host "  No self-updating CAU role found (CAU may still be run in remote-updating mode)." -ForegroundColor DarkYellow
            Add-Flag LOW $cluster.Name "No Cluster-Aware Updating self-updating role detected." `
                -Why "Without coordinated patching, node reboots can collide - or patching quietly stops happening because it is manual and painful." `
                -Fix "Confirm a coordinated method exists (CAU remote-updating, SCVMM, or documented manual drain-patch-resume). If none does, enable CAU: it patches one node at a time with automatic drain and failback."
        }
    } "CAU"
}

# ---- per-node host vitals across the WHOLE cluster (RAM/CPU/uptime, live) ----
$nodeVitals = @()
if ($isCluster) {
    Section "CLUSTER - PER-NODE HOST VITALS (all nodes, live)"
    $nodeVitals = foreach ($n in $nodes) {
        try {
            $os  = Get-CimInstance Win32_OperatingSystem -ComputerName $n -EA Stop
            $csy = Get-CimInstance Win32_ComputerSystem  -ComputerName $n -EA Stop
            $cpu = (Get-CimInstance Win32_Processor -ComputerName $n -EA SilentlyContinue | Measure-Object -Property LoadPercentage -Average).Average
            $tot  = [math]::Round($os.TotalVisibleMemorySize/1MB,2)
            $free = [math]::Round($os.FreePhysicalMemory/1MB,2)
            $used = if ($tot -gt 0) { [math]::Round((($tot-$free)/$tot)*100,1) } else { 0 }
            $upd  = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays,1)
            if ($used -ge 90) {
                Add-Flag MEDIUM $n "Physical RAM $used% used (only $free GB free)." `
                    -Why "A host this full has no headroom for failover, dynamic-memory growth, or usage spikes - VMs will balloon-squeeze or fail to start." `
                    -Fix "Rebalance VMs across nodes, right-size overprovisioned guests, or add RAM."
            }
            if ($upd -gt $MaxUptimeDays) {
                Add-Flag MEDIUM $n "Uptime $([math]::Round($upd,0)) days (> $MaxUptimeDays)." `
                    -Why "Likely missed monthly patch/reboot cycles on this node." `
                    -Fix "Verify patch compliance and schedule a drain + reboot."
            }
            [pscustomobject]@{
                Node=$n; CPU_Pct=$cpu; LogProcs=$csy.NumberOfLogicalProcessors
                RAM_Total_GB=$tot; RAM_Free_GB=$free; RAM_Used_Pct=$used
                UptimeDays=$upd; Build=$os.BuildNumber; Model=$csy.Model
            }
        } catch {
            Write-Host "  [skip] node $n unreachable for host vitals: $($_.Exception.Message)" -ForegroundColor DarkYellow
            Add-Flag INFO $n "Could not read host vitals from this node remotely." `
                -Why "The cross-node view is incomplete - this node's RAM/CPU/uptime were not assessed." `
                -Fix "Run the script directly on $n for its full host detail."
        }
    }
    $nodeVitals | Format-Table -AutoSize
    Write-Host "  RAM here is LIVE utilization (what the OS is using now) - distinct from the static assigned-RAM view in the N+1 check." -ForegroundColor DarkGray
}

# -------------------------------------------------------- Hyper-V host ---
Section "HYPER-V HOST"
$vmHost = $null
Safe {
    $script:vmHost = Get-VMHost
    $vmHost | Select-Object ComputerName,LogicalProcessorCount,
        @{n='MemoryGB';e={[math]::Round($_.MemoryCapacity/1GB,2)}},
        VirtualMachinePath,VirtualHardDiskPath,NumaSpanningEnabled,
        MaximumVirtualMachineMigrations,MaximumStorageMigrations,
        VirtualMachineMigrationEnabled,VirtualMachineMigrationAuthenticationType,
        VirtualMachineMigrationPerformanceOption | Format-List
    if ($vmHost.MaximumVirtualMachineMigrations -lt 2) {
        Add-Flag LOW $env:COMPUTERNAME "Live migration limit is $($vmHost.MaximumVirtualMachineMigrations) (default is 2)." `
            -Why "A low simultaneous-migration limit makes node draining slow, which makes patching slow, which makes patching get skipped." `
            -Fix "Raise it modestly if your network can take it (typically 2-4 on 10 GbE)."
    }
} "VMHost"

# -------------------------------------------------------------- storage ---
Section "STORAGE - CONNECTION TYPE (FC vs iSCSI)"
Safe { Get-InitiatorPort | Select-Object InstanceName,ConnectionType,PortAddress,OperationalStatus | Format-Table -AutoSize } "InitiatorPort"

$iscsiInUse = $false
Section "STORAGE - iSCSI SESSIONS & PERSISTENCE"
Safe {
    $t = Get-IscsiTarget -EA SilentlyContinue
    if ($t) { $script:iscsiInUse = $true; $t | Select-Object NodeAddress,IsConnected | Format-Table -AutoSize }
    Get-IscsiSession -EA SilentlyContinue | Select-Object TargetNodeAddress,NumberOfConnections,IsPersistent | Format-Table -AutoSize
} "iSCSI"
if ($iscsiInUse) {
    Write-Host "Persistent (auto-reconnect-on-boot) targets:" -ForegroundColor Yellow
    $pt = (iscsicli ListPersistentTargets) 2>$null
    $pt
    $ptMatches = ($pt | Select-String 'Total of\s+(\d+)').Matches
    $ptCount = 0
    if ($ptMatches.Count -gt 0) { $ptCount = [int]$ptMatches[0].Groups[1].Value }
    if ($ptCount -eq 0) {
        Add-Flag HIGH $env:COMPUTERNAME "iSCSI in use but 0 persistent targets registered." `
            -Why "After the next reboot the host may NOT reconnect to its SAN storage - which means VMs do not come back either. This is the outage you discover at 6 a.m." `
            -Fix "Re-add the targets with 'Add to favorites / make persistent' checked (iscsicpl.exe), then verify with 'iscsicli ListPersistentTargets'."
    }
}

Section "STORAGE - DISKS / LUNs"
Safe {
    $disks = Get-Disk | Sort-Object Number
    $disks | Select-Object Number,FriendlyName,
        @{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}},PartitionStyle,BusType,
        OperationalStatus,HealthStatus,IsClustered | Format-Table -AutoSize
    foreach ($d in ($disks | Where-Object { $_.HealthStatus -and $_.HealthStatus -ne 'Healthy' })) {
        Add-Flag HIGH "Disk $($d.Number)" "'$($d.FriendlyName)' health is $($d.HealthStatus)." `
            -Why "A degraded physical disk under a hypervisor is a data-loss countdown for every VM stored on it." `
            -Fix "Check the storage vendor tools/SAN console immediately; replace failing hardware and verify redundancy state."
    }
} "Disks"

Section "STORAGE - MULTIPATH (MPIO)"
Safe { mpclaim -s -d } "mpclaim"

if ($isCluster) {
    Section "STORAGE - CLUSTER SHARED VOLUMES + FREE SPACE"
    Safe {
        Get-ClusterSharedVolume | ForEach-Object {
            $csv=$_; $csv.SharedVolumeInfo | ForEach-Object {
                $pctFree=[math]::Round($_.Partition.PercentFree,1)
                [pscustomobject]@{ CSV=$csv.Name; State=$csv.State; Owner=$csv.OwnerNode.Name
                    MountPoint=$_.FriendlyVolumeName
                    SizeGB=[math]::Round($_.Partition.Size/1GB,2)
                    FreeGB=[math]::Round($_.Partition.FreeSpace/1GB,2); PercentFree=$pctFree }
                if ($pctFree -lt 10) {
                    Add-Flag HIGH $csv.Name "Cluster Shared Volume only $pctFree% free." `
                        -Why "Dynamically expanding VHDX files that cannot grow PAUSE their VMs - a full CSV takes workloads down without warning." `
                        -Fix "Extend the volume or reclaim space now (old checkpoints and orphaned VHDX files are the usual suspects)."
                } elseif ($pctFree -lt 20) {
                    Add-Flag MEDIUM $csv.Name "Cluster Shared Volume at $pctFree% free." `
                        -Why "Below 20% there is little room for disk growth, checkpoint chains, or storage migrations." `
                        -Fix "Plan capacity before it becomes the HIGH version of this flag."
                }
            }
        } | Format-Table -AutoSize
    } "CSV"
    Section "STORAGE - CLUSTER PHYSICAL DISK RESOURCES (incl. quorum)"
    Safe { Get-ClusterResource | Where-Object ResourceType -eq 'Physical Disk' |
            Select-Object Name,State,OwnerGroup,OwnerNode | Format-Table -AutoSize } "ClusterDisks"
}

Section "STORAGE - ALL VOLUMES"
Safe {
    $vols = Get-Volume | Sort-Object DriveLetter
    $vols | Select-Object DriveLetter,FileSystemLabel,FileSystem,
        @{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}},
        @{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,2)}},HealthStatus | Format-Table -AutoSize
    foreach ($v in ($vols | Where-Object { $_.DriveLetter -and $_.Size -gt 20GB })) {
        $pctFree = [math]::Round(100 * $v.SizeRemaining / $v.Size, 1)
        if ($pctFree -lt 10) {
            Add-Flag HIGH "$env:COMPUTERNAME $($v.DriveLetter):" "Volume at $pctFree% free ($([math]::Round($v.SizeRemaining/1GB,1)) GB)." `
                -Why "If virtual disks live here they can fail to grow and pause VMs; if this is the OS volume, the host itself becomes unstable." `
                -Fix "Free space or extend the volume. Keep 20%+ free on any volume holding growing VHDX files."
        }
    }
} "Volumes"

# -------------------------------------------------------------- network ---
Section "NETWORK - PHYSICAL NICs"
Safe { Get-NetAdapter | Sort-Object Name | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress | Format-Table -AutoSize } "NICs"

Section "NETWORK - HARDWARE ACCELERATION (VMQ / RSS / SR-IOV)"
Safe {
    Write-Host "VMQ:" -ForegroundColor Yellow
    Get-NetAdapterVmq   -EA SilentlyContinue | Select-Object Name,Enabled | Format-Table -AutoSize | Out-Host
    Write-Host "RSS:" -ForegroundColor Yellow
    Get-NetAdapterRss   -EA SilentlyContinue | Select-Object Name,Enabled,NumberOfReceiveQueues | Format-Table -AutoSize | Out-Host
    Write-Host "SR-IOV:" -ForegroundColor Yellow
    Get-NetAdapterSriov -EA SilentlyContinue | Select-Object Name,Enabled,NumVFs | Format-Table -AutoSize | Out-Host
    foreach ($a in (Get-NetAdapter -Physical -EA SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        $speedNum = 0.0; [double]::TryParse(($a.LinkSpeed -replace '[^\d.]',''), [ref]$speedNum) | Out-Null
        $isGbps = $a.LinkSpeed -match 'Gbps'
        if ($isGbps -and $speedNum -ge 10) {
            $rss = Get-NetAdapterRss -Name $a.Name -EA SilentlyContinue
            if ($rss -and -not $rss.Enabled) {
                Add-Flag LOW $a.Name "RSS disabled on a 10G+ NIC." `
                    -Why "Without Receive Side Scaling, all receive traffic lands on ONE CPU core - a single-core bottleneck that caps throughput far below what the NIC can do." `
                    -Fix "Enable RSS on the adapter (vendor driver page or Enable-NetAdapterRss, run by a human in a window)."
            }
        }
        if ($isGbps -and $speedNum -ge 0.9 -and $speedNum -le 1.1) {
            $vmq = Get-NetAdapterVmq -Name $a.Name -EA SilentlyContinue
            if ($vmq -and $vmq.Enabled) {
                Add-Flag MEDIUM $a.Name "VMQ is enabled on a 1 GbE adapter ($($a.InterfaceDescription))." `
                    -Why "VMQ on 1 GbE NICs (notoriously certain Broadcom models) is the classic cause of mysteriously slow VM networking and packet loss. VMQ only pays off at 10 GbE and above." `
                    -Fix "Disable VMQ on 1 GbE adapters (Disable-NetAdapterVmq, in a maintenance window - it blips the NIC)."
            }
        }
    }
} "NetAccel"

Section "NETWORK - TEAMING (LBFO)"
Safe {
    $lbfo = Get-NetLbfoTeam -EA SilentlyContinue
    if ($lbfo) { $lbfo | Select-Object Name,Members,TeamingMode,LoadBalancingAlgorithm,Status | Format-List
                 Add-Flag LOW ($lbfo.Name -join ',') "Legacy LBFO teaming present." `
                     -Why "LBFO under a Hyper-V vSwitch is deprecated (unsupported for new vSwitches since Server 2022) and misses modern offloads." `
                     -Fix "Plan a migration to Switch Embedded Teaming (SET) at the next rebuild or maintenance cycle." }
    else { Write-Host "  No LBFO teams." -ForegroundColor DarkGray }
} "LBFO"

Section "NETWORK - VIRTUAL SWITCHES"
Safe { Get-VMSwitch | Select-Object Name,SwitchType,EmbeddedTeamingEnabled,AllowManagementOS,NetAdapterInterfaceDescription | Format-List } "vSwitch"
Safe { Get-VMSwitchTeam -EA SilentlyContinue | Select-Object Name,NetAdapterInterfaceDescription,TeamingMode,LoadBalancingAlgorithm | Format-List } "SET"

Section "NETWORK - IP ADDRESSES"
Safe { Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } |
        Select-Object InterfaceAlias,IPAddress,PrefixLength | Sort-Object InterfaceAlias | Format-Table -AutoSize } "IP"

Section "NETWORK - JUMBO FRAMES (iSCSI NICs should be ~9014)"
Safe {
    $jumbo = Get-NetAdapterAdvancedProperty -DisplayName "*Jumbo*" -EA SilentlyContinue
    $jumbo | Select-Object Name,DisplayName,DisplayValue | Format-Table -AutoSize
    foreach ($j in $jumbo) {
        $val = ($j.RegistryValue | Select-Object -First 1)
        $num = 0; [int]::TryParse(("$val" -replace '\D',''),[ref]$num) | Out-Null
        if ($j.Name -match 'iscsi|storage' -and $num -gt 0 -and $num -lt 9000) {
            Add-Flag MEDIUM $j.Name "iSCSI adapter has jumbo frames off ($val)." `
                -Why "Standard 1500-byte frames waste CPU and bandwidth on storage traffic - throughput left on the table on every read and write." `
                -Fix "Enable ~9014-byte jumbo frames END-TO-END (NIC, switch ports, SAN) - enabling it on only one hop makes things worse, so change all three together."
        }
    }
} "Jumbo"

if ($isCluster) {
    Section "NETWORK - CLUSTER NETWORKS + ROLES"
    Safe { Get-ClusterNetwork | Select-Object Name,State,Role,Address,AddressMask | Format-Table -AutoSize
           Write-Host "Role: 0=None/storage  1=Cluster only  3=Cluster+Client" -ForegroundColor DarkGray } "ClusterNet"
    Section "NETWORK - CLUSTER INTERFACES (per node)"
    Safe {
        $ifs = Get-ClusterNetworkInterface
        $ifs | Select-Object Name,Node,Network,State | Sort-Object Node,Network | Format-Table -AutoSize
        foreach ($i in ($ifs | Where-Object State -ne 'Up')) {
            Add-Flag HIGH "$($i.Node)/$($i.Name)" "Cluster interface is $($i.State) (network '$($i.Network)')." `
                -Why "A down cluster interface removes a redundancy path - the next failure that would have been survivable becomes an outage." `
                -Fix "Check cabling, switch port, and NIC on that node; restore the path."
        }
    } "ClusterIfs"
}

# ------------------------------------------------------------------- VMs ---
Section "VIRTUAL MACHINES - CONFIG SUMMARY"
$allVMs = @()
foreach ($n in $nodes) {
    Safe {
        $vms = if ($n -eq $env:COMPUTERNAME) { Get-VM } else { Get-VM -ComputerName $n }
        foreach ($vm in $vms) {
            $script:allVMs += [pscustomobject]@{
                Host=$n; Name=$vm.Name; State=[string]$vm.State; Gen=$vm.Generation
                vCPU=$vm.ProcessorCount; DynMem=$vm.DynamicMemoryEnabled
                AssignedGB=[math]::Round($vm.MemoryAssigned/1GB,2)
                StartGB=[math]::Round($vm.MemoryStartup/1GB,2)
                MaxGB=[math]::Round($vm.MemoryMaximum/1GB,2)
                AutoStart=[string]$vm.AutomaticStartAction
                AutoStop=[string]$vm.AutomaticStopAction
                ProbableDC=($vm.Name -match $DomainControllerPattern)
            }
        }
    } "Get-VM($n)"
}
if ($allVMs.Count -eq 0 -and $isCluster -and $nodes.Count -gt 1) {
    Add-Flag INFO 'cluster' "Could not read VMs from all nodes remotely." `
        -Why "The VM inventory below may be incomplete." `
        -Fix "Re-run the script on each node if the cross-node list looks short."
}
$allVMs | Sort-Object Host,Name |
    Select-Object Host,Name,State,Gen,vCPU,DynMem,AssignedGB,StartGB,MaxGB,AutoStart | Format-Table -AutoSize

# ---- memory model & right-size flags ----
$staticRunning = @($allVMs | Where-Object { $_.State -eq 'Running' -and -not $_.DynMem })
if ($staticRunning.Count -gt 0) {
    Add-Flag INFO 'VMs' ("Dynamic Memory is OFF on {0} running VM(s)." -f $staticRunning.Count) `
        -Why "Static RAM is reserved in full whether the guest uses it or not, and cannot flex during failover. (Static IS correct for SQL Server, Exchange, and domain controllers.)" `
        -Fix "Review each: general-purpose VMs usually benefit from Dynamic Memory with a sane maximum; leave database/AD workloads static."
}
foreach ($vm in ($allVMs | Where-Object { -not $_.DynMem -and $_.AssignedGB -ge 32 })) {
    Add-Flag INFO $vm.Name "Uses $($vm.AssignedGB) GB static RAM." `
        -Why "Large static allocations are the most common source of wasted host capacity - RAM parked 'just in case'." `
        -Fix "Compare against actual demand in the LIVE UTILIZATION section; right-size if demand is far below assigned."
}
foreach ($vm in ($allVMs | Where-Object { $_.MaxGB -ge 1024 })) {
    Add-Flag INFO $vm.Name "MemoryMaximum is at the 1 TB default ($($vm.MaxGB) GB)." `
        -Why "With Dynamic Memory enabled and no real cap, one leaky guest can balloon until it starves every other VM on the host." `
        -Fix "Set a realistic maximum before (or when) enabling Dynamic Memory."
}
foreach ($vm in ($allVMs | Where-Object { $_.ProbableDC -and $_.DynMem })) {
    Add-Flag MEDIUM $vm.Name "Probable domain controller is using Dynamic Memory." `
        -Why "Microsoft recommends fixed memory for DCs - the AD database cache does not cooperate with memory ballooning, and DC performance becomes erratic." `
        -Fix "Switch this DC to static memory sized for its real workload (requires a shutdown window)."
}
foreach ($vm in ($allVMs | Where-Object { $_.AutoStop -eq 'TurnOff' })) {
    Add-Flag MEDIUM $vm.Name "Automatic stop action is 'TurnOff'." `
        -Why "On host shutdown this VM gets hard power-cut - the virtual equivalent of pulling the plug, with the guest-corruption risk that implies." `
        -Fix "Change to 'Save' (default) or 'ShutDown' in VM settings (takes effect without downtime)."
}

# ---- vCPU oversubscription per node ----
$lpByNode = @{}
foreach ($nv in $nodeVitals) { $lpByNode[$nv.Node] = [int]$nv.LogProcs }
if (-not $lpByNode.ContainsKey($env:COMPUTERNAME) -and $cs) { $lpByNode[$env:COMPUTERNAME] = [int]$cs.NumberOfLogicalProcessors }
foreach ($n in ($allVMs | Group-Object Host)) {
    if (-not $lpByNode.ContainsKey($n.Name)) { continue }
    $lp = $lpByNode[$n.Name]; if ($lp -le 0) { continue }
    $vcpu = ($n.Group | Where-Object State -eq 'Running' | Measure-Object vCPU -Sum).Sum
    if (-not $vcpu) { continue }
    $ratio = [math]::Round($vcpu / $lp, 1)
    if ($ratio -gt 8) {
        Add-Flag HIGH $n.Name "vCPU oversubscription is ${ratio}:1 ($vcpu vCPU on $lp logical processors)." `
            -Why "Above roughly 8:1 even light workloads queue for CPU time - everything feels slow and nobody can say why." `
            -Fix "Reduce vCPU counts (most small-business VMs run fine on 2) or add host capacity."
    } elseif ($ratio -gt 4) {
        Add-Flag LOW $n.Name "vCPU oversubscription is ${ratio}:1." `
            -Why "Acceptable for light workloads; worth watching if users report sluggishness." `
            -Fix "Monitor 'CPU Wait Time Per Dispatch' on the busiest VMs before adding vCPUs anywhere."
    } else {
        Add-Flag OK $n.Name "vCPU oversubscription is ${ratio}:1 - healthy."
    }
}

# ---- DCs sharing a host ----
foreach ($grp in ($allVMs | Where-Object ProbableDC | Group-Object Host)) {
    if ($grp.Count -ge 2) {
        Add-Flag MEDIUM $grp.Name "$($grp.Count) probable domain controllers on the same host ($(($grp.Group.Name) -join ', '))." `
            -Why "One host failure takes down all of them at once - and with it, logins, DNS, and everything that leans on AD." `
            -Fix "Keep at least one DC on separate hardware, and set anti-affinity in clusters so they never co-locate."
    }
}

# ---------------------------------------- VM live utilization ---
Section "VIRTUAL MACHINES - LIVE UTILIZATION (CPU% and memory demand vs assigned)"
foreach ($n in $nodes) {
    Safe {
        $vms = if ($n -eq $env:COMPUTERNAME) { Get-VM } else { Get-VM -ComputerName $n }
        $rows = foreach ($vm in ($vms | Where-Object State -eq 'Running')) {
            $asg = [math]::Round($vm.MemoryAssigned/1GB,2)
            $dem = [math]::Round($vm.MemoryDemand/1GB,2)
            $pct = if ($asg -gt 0) { [math]::Round(($dem/$asg)*100,0) } else { 0 }
            if ($asg -gt 0 -and $dem -gt $asg) {
                Add-Flag MEDIUM $vm.Name "Memory demand $dem GB exceeds assigned $asg GB ($pct%)." `
                    -Why "The guest is paging internally - the OS inside the VM is thrashing its page file, which makes everything in that VM slow." `
                    -Fix "Assign more RAM, or enable Dynamic Memory with a higher maximum so the host can respond to demand."
            }
            [pscustomobject]@{ Host=$n; VM=$vm.Name; CPU_Pct=$vm.CPUUsage; Assigned_GB=$asg; Demand_GB=$dem; Demand_Pct=$pct }
        }
        $rows | Sort-Object Demand_Pct -Descending | Format-Table -AutoSize | Out-Host
    } "VMUtil($n)"
}

# ---------------------------------------------- VHD provisioned vs actual ---
Section "VIRTUAL MACHINES - DISKS: PROVISIONED vs ACTUAL"
$vhdTotalsProv = 0.0; $vhdTotalsAct = 0.0
$systemDrive = $env:SystemDrive
foreach ($n in $nodes) {
    Safe {
        $vms = if ($n -eq $env:COMPUTERNAME) { Get-VM } else { Get-VM -ComputerName $n }
        foreach ($vm in $vms) {
            foreach ($hd in ($vm | Get-VMHardDiskDrive)) {
                try {
                    $v = if ($n -eq $env:COMPUTERNAME) { Get-VHD -Path $hd.Path -EA Stop } else { Get-VHD -ComputerName $n -Path $hd.Path -EA Stop }
                    $prov=[math]::Round($v.Size/1GB,2); $act=[math]::Round($v.FileSize/1GB,2)
                    $script:vhdTotalsProv += $prov; $script:vhdTotalsAct += $act
                    $parent = if ($v.ParentPath) { Split-Path $v.ParentPath -Leaf } else { '' }
                    [pscustomobject]@{ Host=$n; VM=$vm.Name; Type=$v.VhdType; ProvGB=$prov; ActualGB=$act; Parent=$parent; Path=$hd.Path } |
                        Format-Table -AutoSize | Out-Host
                    if ($isCluster -and $hd.Path -notmatch 'ClusterStorage') {
                        Add-Flag HIGH $vm.Name "Disk is NOT on cluster shared storage ($($hd.Path))." `
                            -Why "A clustered VM with local-only storage cannot fail over - when its node dies, this VM dies with it, cluster or no cluster." `
                            -Fix "Storage-migrate the disk onto a CSV (live operation, run by a human in a window)."
                    }
                    if ($v.VhdType -eq 'Differencing' -or $v.ParentPath) {
                        Add-Flag MEDIUM $vm.Name "Uses a differencing disk (parent: $parent)." `
                            -Why "Differencing chains add I/O overhead on every read, and if the parent moves or corrupts, every child dies. Fine for labs; risky in production." `
                            -Fix "Merge the chain if it is not intentional (Merge-VHD offline, or delete the underlying checkpoint if that is what created it)."
                    }
                    if ([IO.Path]::GetExtension($hd.Path) -ieq '.vhd') {
                        Add-Flag LOW $vm.Name "Legacy .vhd format disk: $(Split-Path $hd.Path -Leaf)" `
                            -Why "VHD caps at 2 TB and lacks VHDX's corruption resilience (power-loss protection) and 4K alignment." `
                            -Fix "Convert to VHDX during a maintenance window (Convert-VHD, VM off)."
                    }
                    if ($n -eq $env:COMPUTERNAME -and $hd.Path -like "$systemDrive\*") {
                        Add-Flag MEDIUM $vm.Name "Virtual disk lives on the host OS drive: $($hd.Path)" `
                            -Why "A growing VHDX can fill the system volume - which pauses the VM AND destabilizes the host itself. Two failures for the price of one." `
                            -Fix "Storage-migrate the disk to a data volume."
                    }
                } catch {
                    Add-Flag INFO $vm.Name "Could not read VHD at $($hd.Path)." `
                        -Why "Disk sizing for this VM is missing from the report." `
                        -Fix "Check the path exists and re-run elevated on the owning node."
                    Write-Host ("  [vhd read error] {0}: {1}" -f $vm.Name, $hd.Path) -ForegroundColor DarkYellow
                }
            }
        }
    } "VHD($n)"
}
Write-Host ("TOTAL provisioned: {0} GB | actual on disk: {1} GB" -f [math]::Round($vhdTotalsProv,2),[math]::Round($vhdTotalsAct,2)) -ForegroundColor Yellow

# ----------------------------------------------------------- checkpoints ---
Section "VIRTUAL MACHINES - CHECKPOINTS"
$anySnap = $false
foreach ($n in $nodes) {
    Safe {
        $vms = if ($n -eq $env:COMPUTERNAME) { Get-VM } else { Get-VM -ComputerName $n }
        $snaps = $vms | Get-VMSnapshot -EA SilentlyContinue
        if ($snaps) {
            $script:anySnap = $true
            $snaps | Select-Object @{n='Host';e={$n}},VMName,Name,SnapshotType,CreationTime | Sort-Object CreationTime | Format-Table -AutoSize | Out-Host
            $dcSnapVMs = @()
            foreach ($s in $snaps) {
                if ($s.VMName -match $DomainControllerPattern -and $dcSnapVMs -notcontains $s.VMName) {
                    $dcSnapVMs += $s.VMName
                    Add-Flag HIGH $s.VMName "Probable domain controller has checkpoint(s)." `
                        -Why "Applying an old DC checkpoint can cause USN rollback - AD replication breaks silently, domain-wide, and the cleanup is brutal. Checkpoints on DCs are a standing hazard." `
                        -Fix "Remove the checkpoints (they merge automatically). Protect DCs with proper backups instead."
                    continue
                }
                $age = (New-TimeSpan -Start $s.CreationTime -End (Get-Date)).Days
                if ($age -ge $CheckpointAgeDays) {
                    Add-Flag MEDIUM $s.VMName "Checkpoint is $age days old." `
                        -Why "Old checkpoints grow AVHDX chains that eat disk and slow every I/O. Checkpoints are NOT backups - they were designed to cover a change window, not to live for weeks." `
                        -Fix "Confirm the change they covered is good, then delete them (merges automatically, no downtime for most workloads)."
                }
            }
        }
    } "Snapshots($n)"
}
if (-not $anySnap) { Write-Host "  No checkpoints found (good)." -ForegroundColor Green }

# -------------------------------------------------- integration services ---
Section "VIRTUAL MACHINES - INTEGRATION SERVICES"
foreach ($n in $nodes) {
    Safe {
        $vms = if ($n -eq $env:COMPUTERNAME) { Get-VM } else { Get-VM -ComputerName $n }
        $vms | ForEach-Object {
            $s = $_ | Get-VMIntegrationService
            $hb  = ($s | Where-Object { $_.Name -eq 'Heartbeat' }).Enabled
            $vss = ($s | Where-Object { $_.Name -eq 'VSS' }).Enabled
            if ($hb -eq $false) {
                Add-Flag LOW $_.Name "Heartbeat integration service is disabled." `
                    -Why "Monitoring and the cluster cannot tell whether the guest OS is alive - failure detection goes blind." `
                    -Fix "Enable it in VM settings > Integration Services (no downtime)."
            }
            if ($vss -eq $false) {
                Add-Flag MEDIUM $_.Name "VSS (backup) integration service is disabled." `
                    -Why "Backups of this VM cannot be application-consistent - restores may come back as if the server had crashed mid-write." `
                    -Fix "Enable it in VM settings > Integration Services, then verify the next backup completes app-consistent."
            }
            [pscustomobject]@{ Host=$n; VM=$_.Name
                Heartbeat=$hb
                TimeSync=($s | Where-Object { $_.Name -eq 'Time Synchronization' }).Enabled
                GuestSvc=($s | Where-Object { $_.Name -eq 'Guest Service Interface' }).Enabled
                VSS=$vss }
        } | Format-Table -AutoSize | Out-Host
    } "IntegrationSvc($n)"
}
Write-Host "  Note: Time Sync OFF is CORRECT on domain controllers - verify role before 'fixing'." -ForegroundColor DarkGray

# ------------------------------------ VM platform currency ---
Section "VIRTUAL MACHINES - PLATFORM CURRENCY (config version & guest tools)"
foreach ($n in $nodes) {
    Safe {
        $vms = if ($n -eq $env:COMPUTERNAME) { Get-VM } else { Get-VM -ComputerName $n }
        $rows = foreach ($vm in $vms) {
            if ($vm.IntegrationServicesState -and $vm.IntegrationServicesState -match 'require|older|mismatch') {
                Add-Flag LOW $vm.Name "Guest integration services: '$($vm.IntegrationServicesState)'." `
                    -Why "Outdated guest components mean degraded drivers, time drift, and backup glitches inside the VM." `
                    -Fix "Update the guest OS (integration components ship via Windows Update on modern guests)."
            }
            [pscustomobject]@{ Host=$n; VM=$vm.Name; ConfigVersion=$vm.Version; IntegrationSvc=$vm.IntegrationServicesState }
        }
        $rows | Format-Table -AutoSize | Out-Host
    } "VMCurrency($n)"
}
Write-Host "  A config version well below the host's maximum = upgrade candidate (VM must be OFF; the upgrade is one-way)." -ForegroundColor DarkGray

# -------------------------------------- VM security posture ---
Section "VIRTUAL MACHINES - SECURITY (Gen 2: Secure Boot / vTPM)"

foreach ($n in $nodes) {
    Safe {
        $vms = if ($n -eq $env:COMPUTERNAME) {
            Get-VM
        }
        else {
            Get-VM -ComputerName $n
        }

        $rows = foreach ($vm in ($vms | Where-Object Generation -eq 2)) {

            # Get firmware configuration
            $firmware = if ($n -eq $env:COMPUTERNAME) {
                Get-VMFirmware -VMName $vm.Name
            }
            else {
                Get-VMFirmware -ComputerName $n -VMName $vm.Name
            }

            # Get security configuration
            $sec = $vm | Get-VMSecurity

            # Get-VMFirmware reports SecureBoot as On / Off
            $secureBoot = ($firmware.SecureBoot -eq 'On')

            # Get-VMSecurity reports TPM state
            $vTPM = [bool]$sec.TpmEnabled

            if (-not $secureBoot) {
                Add-Flag LOW $vm.Name "Gen 2 VM has Secure Boot disabled." `
                    -Why "Secure Boot prevents unsigned or unauthorised boot components from loading before the operating system." `
                    -Fix "Enable Secure Boot unless the guest OS genuinely requires it to remain disabled. For supported Linux guests, use the Microsoft UEFI Certificate Authority template."
            }

            [pscustomobject]@{
                Host       = $n
                VM         = $vm.Name
                SecureBoot = $firmware.SecureBoot
                vTPM       = $vTPM
            }
        }

        $rows | Format-Table -AutoSize | Out-Host

    } "VMSecurity($n)"
}

# ----------------------------------------------------- VM networking/VLAN ---
Section "VIRTUAL MACHINES - NETWORK ADAPTERS & VLAN"
$vlansSeen = @()
foreach ($n in $nodes) {
    Safe {
        $vms = if ($n -eq $env:COMPUTERNAME) { Get-VM } else { Get-VM -ComputerName $n }
        $vms | Get-VMNetworkAdapter | ForEach-Object {
            $vl = $_ | Get-VMNetworkAdapterVlan
            $script:vlansSeen += "$($vl.OperationMode):$($vl.AccessVlanId)"
            [pscustomobject]@{ Host=$n; VM=$_.VMName; Switch=$_.SwitchName
                VLANmode=$vl.OperationMode; VLANid=$vl.AccessVlanId; Connected=$_.Connected }
        } | Format-Table -AutoSize | Out-Host
    } "VMNet($n)"
}
if (($vlansSeen | Sort-Object -Unique).Count -le 1 -and $allVMs.Count -gt 3) {
    Add-Flag INFO 'network' "All VMs share one flat network (no VLAN segmentation)." `
        -Why "Flat networks mean any compromised VM can reach every other VM - no blast-radius control." `
        -Fix "Review against your security requirements; segment servers from workstations/guests where it matters."
}

# ---------------------------------------------- cluster VM priority / HA ---
if ($isCluster) {
    Section "CLUSTER - VM ROLES & PRIORITY (failover order)"
    Safe {
        $grp = Get-ClusterGroup | Where-Object GroupType -eq 'VirtualMachine'
        $grp | Select-Object Name,State,OwnerNode,
            @{n='Priority';e={ switch($_.Priority){3000{'High'}2000{'Medium'}1000{'Low'}0{'NoAutoStart'}default{$_.Priority}} }} |
            Sort-Object Priority -Descending | Format-Table -AutoSize
        foreach ($g in ($grp | Where-Object State -eq 'Offline')) {
            Add-Flag MEDIUM $g.Name "Clustered VM is Offline." `
                -Why "Either it is intentional (retired/template) or something failed and nobody noticed - both are worth knowing." `
                -Fix "Confirm with the owner; remove retired roles from the cluster so the console reflects reality."
        }
        # DC anti-affinity
        $dcGroups = @($grp | Where-Object { $_.Name -match $DomainControllerPattern })
        $noAffinity = @($dcGroups | Where-Object { -not $_.AntiAffinityClassNames })
        if ($dcGroups.Count -ge 2 -and $noAffinity.Count -gt 0) {
            Add-Flag MEDIUM ($dcGroups.Name -join ', ') "Clustered probable-DC roles have no anti-affinity classes set." `
                -Why "Nothing stops the cluster from landing every domain controller on the same node - where one node failure takes AD down entirely." `
                -Fix "Set the same class on all DC roles: (Get-ClusterGroup 'DC-VM').AntiAffinityClassNames = 'DomainControllers' (run by a human)."
        }
    } "Priority"
}

# ------------------------------------------------ N+1 FAILOVER CAPACITY ---
$nPlusOne = $null
if ($isCluster -and $nodes.Count -ge 2) {
    Section "CLUSTER - N+1 FAILOVER CAPACITY CHECK"
    Safe {
        $report = foreach ($n in $nodes) {
            $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem -ComputerName $n).TotalPhysicalMemory/1GB,2)
            $here = $allVMs | Where-Object { $_.Host -eq $n -and $_.State -eq 'Running' }
            [pscustomobject]@{ Node=$n; PhysRAM_GB=$ram
                AssignedRAM_GB=[math]::Round(($here|Measure-Object AssignedGB -Sum).Sum,2)
                FreeRAM_GB=[math]::Round($ram-($here|Measure-Object AssignedGB -Sum).Sum,2)
                RunningVMs=$here.Count }
        }
        $report | Format-Table -AutoSize | Out-Host
        $totalRAM = [math]::Round((($allVMs|Where-Object State -eq 'Running')|Measure-Object AssignedGB -Sum).Sum,2)
        $smallest = ($report | Sort-Object PhysRAM_GB | Select-Object -First 1)
        Write-Host ("Total running-VM RAM across cluster : {0} GB" -f $totalRAM) -ForegroundColor Yellow
        Write-Host ("Smallest node physical RAM          : {0} GB (reserve {1} GB)" -f $smallest.PhysRAM_GB,$MemoryReserveGB) -ForegroundColor Yellow
        if ($totalRAM -le ($smallest.PhysRAM_GB - $MemoryReserveGB)) {
            Write-Host "N+1 OK: one node can absorb everything on failover." -ForegroundColor Green
            $script:nPlusOne = 'PASS'
            Add-Flag OK 'cluster' "N+1 failover capacity: PASS ($totalRAM GB of running VMs fits a $($smallest.PhysRAM_GB) GB survivor with $MemoryReserveGB GB reserved)."
        } else {
            Write-Host "N+1 FAIL: on a single-node failure the survivor would be OVERCOMMITTED." -ForegroundColor Red
            $script:nPlusOne = 'FAIL'
            Add-Flag HIGH 'cluster' ("N+1 failover shortfall: {0} GB of running VMs vs a {1} GB survivor (reserve {2} GB)." -f $totalRAM,$smallest.PhysRAM_GB,$MemoryReserveGB) `
                -Why "The cluster LOOKS highly available, but if a node dies today, some VMs will not restart - you find out which ones during the outage." `
                -Fix "Right-size overprovisioned VMs (see live utilization), convert suitable workloads to Dynamic Memory, or add node RAM until everything fits one node minus the OS reserve."
        }
    } "N+1"
}

# --------------------------------------- Hyper-V Replica / DR ---
Section "VIRTUAL MACHINES - REPLICATION / DR (Hyper-V Replica)"
$anyRep = $false
foreach ($n in $nodes) {
    Safe {
        $reps = if ($n -eq $env:COMPUTERNAME) { Get-VMReplication -EA SilentlyContinue } else { Get-VMReplication -ComputerName $n -EA SilentlyContinue }
        if ($reps) {
            $script:anyRep = $true
            $reps | Select-Object @{n='Host';e={$n}},VMName,Mode,State,Health,PrimaryServer,ReplicaServer | Format-Table -AutoSize | Out-Host
            foreach ($r in $reps) {
                if ($r.Health -eq 'Critical') {
                    Add-Flag HIGH $r.VMName "Hyper-V Replica health CRITICAL (State: $($r.State))." `
                        -Why "The DR copy is not current - if you failed over right now, you would lose everything since the last successful replication." `
                        -Fix "Check connectivity/credentials/disk space on the replica server, then resume or resynchronize replication."
                } elseif ($r.Health -eq 'Warning') {
                    Add-Flag MEDIUM $r.VMName "Hyper-V Replica health Warning (State: $($r.State))." `
                        -Why "Replication is falling behind its RPO - the DR copy is aging." `
                        -Fix "Check bandwidth and replica-side load; investigate before Warning becomes Critical."
                }
            }
        }
    } "VMReplication($n)"
}
if (-not $anyRep) { Write-Host "  No Hyper-V Replica configured on these nodes." -ForegroundColor DarkGray }

# ------------------------------------------------------ FLAGS SUMMARY ---
Section "AUTOMATED FLAGS - TRIAGE SUMMARY"
$order = @{HIGH=0;MEDIUM=1;LOW=2;INFO=3;OK=4}
$sorted = $Flags | Sort-Object { $order[$_.Severity] }
if ($Flags.Count -eq 0) {
    Write-Host "  No issues flagged by automated checks. Still review the detail above." -ForegroundColor Green
} else {
    foreach ($f in $sorted) {
        $c = switch ($f.Severity){'HIGH'{'Red'}'MEDIUM'{'Yellow'}'LOW'{'DarkYellow'}'OK'{'Green'}default{'Gray'}}
        Write-Host ("  [{0,-6}] {1} - {2}" -f $f.Severity,$f.Target,$f.Message) -ForegroundColor $c
    }
    Write-Host ""
    Write-Host ("  Totals -> HIGH: {0}  MEDIUM: {1}  LOW: {2}  INFO: {3}  OK: {4}" -f `
        @($Flags | Where-Object Severity -eq 'HIGH').Count, @($Flags | Where-Object Severity -eq 'MEDIUM').Count,
        @($Flags | Where-Object Severity -eq 'LOW').Count,  @($Flags | Where-Object Severity -eq 'INFO').Count,
        @($Flags | Where-Object Severity -eq 'OK').Count) -ForegroundColor Cyan
}

# ------------------------------------------------------ HTML REPORT ---
$sevColor = @{ HIGH='#c0392b'; MEDIUM='#b07a00'; LOW='#8a6d00'; INFO='#3378ff'; OK='#3d7a00' }
function HtmlEnc { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

$counts = @{}
foreach ($k in 'HIGH','MEDIUM','LOW','INFO','OK') { $counts[$k] = @($Flags | Where-Object Severity -eq $k).Count }

$rowsFindings = ($sorted | ForEach-Object {
    $why = if ($_.Why) { "<div class='why'><b>Why it matters:</b> $(HtmlEnc $_.Why)</div>" } else { '' }
    $fix = if ($_.Fix) { "<div class='fix'><b>What to do:</b> $(HtmlEnc $_.Fix)</div>" } else { '' }
    "<tr><td><span class='sev' style='background:$($sevColor[$_.Severity])'>$($_.Severity)</span></td>" +
    "<td>$(HtmlEnc $_.Target)</td><td><div class='saw'>$(HtmlEnc $_.Message)</div>$why$fix</td></tr>"
}) -join "`n"

$rowsVms = ($allVMs | Sort-Object Host,Name | ForEach-Object {
    $mem = if ($_.DynMem) { "Dynamic $($_.StartGB)&ndash;$($_.MaxGB) GB" } else { "Static $($_.AssignedGB) GB" }
    $dc  = if ($_.ProbableDC) { " <span class='dc'>DC?</span>" } else { '' }
    "<tr><td>$(HtmlEnc $_.Name)$dc</td><td>$(HtmlEnc $_.Host)</td><td>$($_.State)</td><td>$($_.Gen)</td>" +
    "<td>$($_.vCPU)</td><td>$mem</td><td>$(HtmlEnc $_.AutoStart)/$(HtmlEnc $_.AutoStop)</td></tr>"
}) -join "`n"

$rowsNodes = ''
if ($nodeVitals) {
    $rowsNodes = ($nodeVitals | ForEach-Object {
        "<tr><td>$(HtmlEnc $_.Node)</td><td>$($_.CPU_Pct)%</td><td>$($_.LogProcs)</td><td>$($_.RAM_Total_GB)</td>" +
        "<td>$($_.RAM_Free_GB)</td><td>$($_.RAM_Used_Pct)%</td><td>$($_.UptimeDays)d</td><td>$(HtmlEnc $_.Model)</td></tr>"
    }) -join "`n"
}

$clusterLine = if ($isCluster) { "Cluster: $(HtmlEnc $cluster.Name) ($($nodes.Count) nodes up)" } else { 'Standalone host (not clustered)' }
$n1Line = switch ($nPlusOne) {
    'PASS' { "<span class='n1 pass'>N+1 PASS</span>" }
    'FAIL' { "<span class='n1 fail'>N+1 FAIL</span>" }
    default { '' }
}

$html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hyper-V Audit - $(HtmlEnc $env:COMPUTERNAME) - $stamp</title>
<style>
 body{font-family:"Segoe UI",system-ui,sans-serif;margin:0;background:#f7f7f4;color:#1e1f36}
 header{background:#1e1f36;color:#fff;padding:20px 28px}
 header h1{margin:0;font-size:19px} header h1 b{color:#b5ff1b}
 header p{margin:4px 0 0;color:#ffffff99;font-size:13px}
 main{max-width:1120px;margin:0 auto;padding:24px 28px 60px}
 .stats{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0;align-items:center}
 .stat{background:#fff;border:1px solid #e3e3ea;border-radius:10px;padding:10px 18px;font-size:13px}
 .stat b{display:block;font-size:20px}
 .n1{font-weight:700;padding:8px 16px;border-radius:10px;font-size:14px}
 .n1.pass{background:#e6f4d9;color:#3d7a00} .n1.fail{background:#fbe4e0;color:#c0392b}
 h2{font-size:16px;margin:28px 0 8px}
 table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e3e3ea;font-size:13px}
 th,td{text-align:left;padding:9px 11px;border-bottom:1px solid #eee;vertical-align:top}
 th{background:#f0f0ee;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
 .sev{color:#fff;font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:999px;white-space:nowrap}
 .saw{font-weight:600}
 .why{color:#4a4d63;font-size:12.5px;margin-top:4px}
 .fix{color:#1e5c1e;font-size:12.5px;margin-top:3px}
 .dc{background:#fdf3dd;color:#b07a00;font-size:10px;font-weight:700;padding:1px 6px;border-radius:999px}
 footer{margin-top:36px;font-size:12px;color:#6a6d85}
 footer a{color:#3378ff}
</style></head><body>
<header>
 <h1><b>BW</b> &middot; Hyper-V Audit v2.0</h1>
 <p>Host $(HtmlEnc $env:COMPUTERNAME) &middot; $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; $clusterLine &middot; read-only audit, no changes made</p>
</header>
<main>
 <div class="stats">
  <div class="stat"><b>$($allVMs.Count)</b>VMs inventoried</div>
  <div class="stat"><b style="color:#c0392b">$($counts.HIGH)</b>high</div>
  <div class="stat"><b style="color:#b07a00">$($counts.MEDIUM)</b>medium</div>
  <div class="stat"><b style="color:#8a6d00">$($counts.LOW)</b>low</div>
  <div class="stat"><b style="color:#3378ff">$($counts.INFO)</b>info</div>
  <div class="stat"><b style="color:#3d7a00">$($counts.OK)</b>ok</div>
  $n1Line
 </div>
 <h2>Findings - what we saw, why it matters, what to do</h2>
 <table><thead><tr><th>Severity</th><th>Target</th><th>Finding</th></tr></thead>
 <tbody>$rowsFindings</tbody></table>
 $(if ($rowsNodes) { "<h2>Cluster nodes (live vitals)</h2><table><thead><tr><th>Node</th><th>CPU</th><th>LPs</th><th>RAM GB</th><th>Free GB</th><th>Used</th><th>Uptime</th><th>Model</th></tr></thead><tbody>$rowsNodes</tbody></table>" })
 <h2>VM inventory</h2>
 <table><thead><tr><th>VM</th><th>Host</th><th>State</th><th>Gen</th><th>vCPU</th><th>Memory</th><th>Start/Stop action</th></tr></thead>
 <tbody>$rowsVms</tbody></table>
 <p style="font-size:13px">Total VHD provisioned: <b>$([math]::Round($vhdTotalsProv,0)) GB</b> &middot; actual on disk: <b>$([math]::Round($vhdTotalsAct,0)) GB</b></p>
 <Full raw detail is in the accompanying transcript file.
 </footer>
</main></body></html>
"@

$html | Out-File -FilePath $htmlFile -Encoding utf8
Write-Host ""
Write-Host ("HTML report : {0}" -f $htmlFile) -ForegroundColor Green

if ($Json) {
    $jsonFile = Join-Path $OutputFolder "$baseName.json"
    [pscustomobject]@{
        Host      = $env:COMPUTERNAME
        Generated = (Get-Date -Format 'o')
        Cluster   = if ($isCluster) { $cluster.Name } else { $null }
        NPlusOne  = $nPlusOne
        Summary   = $counts
        Findings  = $sorted
        VMs       = $allVMs
        Nodes     = $nodeVitals
    } | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding utf8
    Write-Host ("JSON export : {0}" -f $jsonFile) -ForegroundColor Green
}

Write-Host ""
Write-Host ("Done. {0} findings. Read the HTML report first; the transcript has the raw detail." -f $Flags.Count) -ForegroundColor Green
if (-not $NoTranscript) { Stop-Transcript | Out-Null }
