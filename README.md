# Hyper-V Audit

A single-file PowerShell script that maps a Hyper-V host — or an entire
failover cluster — end to end and audits it against Microsoft best practices.
**Strictly read-only**: no `Set-`, `Enable-`, `Remove-`, or any other
state-changing call against your infrastructure — safe to run on production
during business hours. It reports; it never touches.

Every finding in the HTML report is explained in three parts: **what we saw,
why it matters, what to do** — so the output reads like an engineer's
write-up, not a wall of raw data.

Born from real field assessments: this is the script
[KYTHEL](https://kythel.com) (managed IT services, Boynton Beach, FL) runs
when taking over a Hyper-V environment, released as open source.

## What it checks

**Host stability & patching**
- Uptime beyond the patch cycle, newest installed update age, pending-reboot
  state (CBS / Windows Update / file-rename), BIOS/firmware version

**Cluster** (auto-detected; skipped on standalone hosts)
- Node states, quorum config, missing witness on even-node clusters
- Per-node live vitals across every node (CPU, RAM used, uptime)
- **N+1 failover capacity**: can the smallest surviving node absorb every
  running VM (minus an OS reserve)? PASS/FAIL, with the math shown
- Cluster-Aware Updating posture, cluster networks and per-node interfaces
- Clustered VMs stored off shared storage (they cannot fail over)
- VM priority/failover order, offline roles, DC anti-affinity classes

**Storage / SAN**
- FC vs iSCSI initiator ports, iSCSI sessions, and **persistent targets**
  (0 persistent targets = storage won't reconnect after a reboot)
- Disk/LUN health, MPIO status, CSV free space, all-volume free space
- Per-VHD provisioned vs actual size, differencing-disk chains,
  legacy `.vhd` format, virtual disks on the host OS drive

**Memory & CPU**
- Static vs dynamic per VM (with the exceptions that *should* stay static:
  SQL, Exchange, domain controllers), 1 TB default memory caps
- Live memory demand vs assigned (guest paging detection)
- vCPU:logical-processor oversubscription per node (warn >4:1, alarm >8:1)

**Domain controllers** (heuristic — tune with `-DomainControllerPattern`)
- Checkpoints on DCs (USN-rollback hazard), dynamic memory on DCs,
  multiple DCs sharing one host, anti-affinity in clusters

**Hygiene & security**
- Checkpoints older than N days, disabled Heartbeat/VSS integration services,
  guest-tools currency, VM config versions, "TurnOff" stop actions
- Secure Boot / vTPM posture on Gen 2 VMs, VLAN segmentation review

**Network**
- VMQ on 1 GbE adapters (the classic "VMs are slow and nobody knows why"),
  RSS disabled on 10G+ NICs, SR-IOV state
- Legacy LBFO teams (deprecated) vs Switch Embedded Teaming
- Jumbo frames on iSCSI adapters

**DR**
- Hyper-V Replica health per VM (Critical/Warning states)

## Usage

```powershell
# On the Hyper-V host, in an elevated PowerShell:
.\Invoke-HyperVAudit.ps1

# Custom output folder + JSON export for automation:
.\Invoke-HyperVAudit.ps1 -OutputFolder D:\Reports -Json

# Your DCs are named like "AD01", "CORP-ADDS-2"? Tune the heuristic:
.\Invoke-HyperVAudit.ps1 -DomainControllerPattern 'AD\d|ADDS'

# Tune thresholds:
.\Invoke-HyperVAudit.ps1 -CheckpointAgeDays 14 -MaxUptimeDays 60 -MemoryReserveGB 24
```

You get three things: a sectioned console transcript (saved to a `.txt`), a
self-contained **HTML report** with every finding explained, and optionally a
`.json` for tooling. Run it from any one cluster node and it reaches the
others over the same read-only CIM channel.

## Requirements

- Windows Server 2016+ or Windows 10/11 Pro with the Hyper-V role
- Windows PowerShell 5.1 or PowerShell 7+, elevated (Administrator)
- The Hyper-V PowerShell module (installed with the management tools)
- For cluster-wide detail: the FailoverClusters module and CIM/WinRM
  reachability to the other nodes (sections degrade gracefully if not)

## Safety

The read-only claim is verified statically: parsing the script's AST finds no
state-changing cmdlets against your infrastructure. The only writes it makes
are its own output files (report, transcript, optional JSON). The two external
executables it calls — `mpclaim -s` and `iscsicli ListPersistentTargets` — are
status displays. Every "What to do" recommendation in the report is meant to
be executed by a human, in a change window, after review. Audit the source
yourself — it's one file, and that's on purpose.

## Roadmap

- Storage-path contention checks (multiple busy VMs sharing a spindle)
- Guest-level checks via PowerShell Direct (opt-in)
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
