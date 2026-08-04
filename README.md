# Hyper-V Audit

A single-file PowerShell script that audits a Hyper-V host against Microsoft
best practices and produces a color-coded HTML report. **Strictly read-only**:
it contains no `Set-`, `Enable-`, `Remove-`, or any other state-changing call
against your infrastructure — safe to run on a production host during business
hours. It reports; it never touches.

Built and maintained by [KYTHEL](https://kythel.com), a managed IT services
company in Boynton Beach, Florida. This is the same first-pass audit we run
when we take over an environment, released as open source.

## What it checks

**Memory**
- Static vs dynamic allocation per VM (and which workloads should stay static)
- Worst-case memory commitment vs physical host RAM
- Dynamic memory on probable domain controllers (Microsoft says don't)

**CPU**
- vCPU-to-logical-processor oversubscription ratio, with sane thresholds
  (flags above 4:1, alarms above 8:1)

**Storage**
- Legacy `.vhd` disks that should be VHDX
- Virtual disks living on the host's OS drive
- Host volumes and Cluster Shared Volumes low on free space (dynamically
  expanding disks that can't grow will pause their VMs)

**Hygiene**
- Checkpoints older than 7 days (checkpoints are not backups)
- Checkpoints on domain controllers (USN-rollback hazard — flagged critical)
- Disabled integration services (Heartbeat, KVP, VSS)
- Generation 1 VMs, hard "TurnOff" automatic stop actions
- Host patch age and uptime

**Network**
- VMQ enabled on 1 GbE adapters — the classic "VMs are slow and nobody knows
  why" misconfiguration
- Virtual switch inventory

**Domain controllers** (heuristic — matches VM names against a pattern you
control with `-DomainControllerPattern`)
- Two or more DCs on the same host (one host failure takes AD down with it)
- Time-sync integration service enabled on DCs

**Cluster** (only when the node is clustered)
- CSV free space, quorum witness on even-node clusters
- Cluster-Aware Updating role present
- DC roles without anti-affinity classes

## Usage

```powershell
# On the Hyper-V host, in an elevated PowerShell:
.\Invoke-HyperVAudit.ps1

# Custom report location + JSON export for automation:
.\Invoke-HyperVAudit.ps1 -OutputPath C:\Reports\audit.html -Json

# Your DCs are named like "AD01", "CORP-ADDS-2"? Tune the heuristic:
.\Invoke-HyperVAudit.ps1 -DomainControllerPattern 'AD\d|ADDS'
```

You get a console summary immediately and a self-contained HTML file you can
email, archive, or attach to a change ticket.

## Requirements

- Windows Server 2016+ or Windows 10/11 Pro with the Hyper-V role
- Windows PowerShell 5.1 or PowerShell 7+
- The Hyper-V PowerShell module (installed with the management tools)
- An elevated session for full disk details (`Get-VHD` requires admin;
  everything else degrades gracefully without it)

## Safety

The read-only claim is verified statically: parsing the script's AST finds no
state-changing cmdlets (the only `Set-*` present is `Set-StrictMode`, which
affects the script's own session, not your systems). Audit the source
yourself — it's one file, and that's on purpose.

## Roadmap

- Storage-path deduplication checks (multiple VMs sharing a spindle)
- Replica health (`Get-VMReplication`) checks
- A macOS companion for auditing Mac fleets

Issues and PRs welcome.

## License

[MIT](LICENSE) — use it, fork it, run it for your clients.

---

If your Hyper-V host is a mystery box someone set up years ago, this script
tells you where you stand in about a minute. If you'd rather have a human
fix what it finds: [KYTHEL](https://kythel.com) provides
[managed IT services](https://kythel.com/services/managed-it-services/) and
[IT support](https://kythel.com/services/it-support/) in Palm Beach and
Broward County, Florida. Se habla español.
