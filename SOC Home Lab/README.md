# Windows Security Monitoring & Threat Detection using Splunk

A practical SOC home-lab project for learning Windows security event monitoring, SPL, and basic security investigation using Splunk Enterprise.

## Project Overview

This project demonstrates how Windows Security logs can be collected from a Windows host using the **Splunk Universal Forwarder**, sent to **Splunk Enterprise running on Ubuntu**, and investigated using Splunk Search Processing Language (SPL).

The goal is to practice a basic SOC analyst workflow using real Windows events:

```text
Windows Host
     ↓
Splunk Universal Forwarder
     ↓
Splunk Enterprise (Ubuntu)
     ↓
Windows Security Events
     ↓
SPL Investigation
     ↓
Evidence & Analysis
     ↓
SOC Assessment
```

## Lab Environment

| Component | Setup |
|---|---|
| SIEM | Splunk Enterprise |
| Forwarder | Splunk Universal Forwarder |
| SIEM OS | Ubuntu |
| Endpoint | Windows |
| Log Source | Windows Security Event Log |
| Network | VMware virtual network |
| Main Data | Windows Security Events |

## What I Practiced

- Collecting Windows Security logs with Splunk Universal Forwarder
- Sending Windows events to Splunk Enterprise
- Searching Windows Event IDs with SPL
- Filtering and displaying useful fields
- Counting and sorting events
- Investigating authentication activity
- Investigating process creation
- Examining parent-child process relationships
- Distinguishing normal activity from potentially suspicious activity
- Documenting investigation findings
- Applying evidence-based SOC reasoning

## Investigations

### 001 — Failed Logon (Event ID 4625)

Investigated failed Windows logon events.

Covered:

- Logon Type
- Failure reason
- Status and sub-status codes
- Authentication package
- Source information
- Determining whether failures indicated suspicious activity

**Result:** The observed events were consistent with failed local authentication activity.

---

### 002 — Successful Service Logon (Event ID 4624)

Investigated successful service authentication events.

Covered:

- Successful logon events
- Logon Type 5
- Account context
- Authentication package
- Windows service authentication

**Result:** The observed events were consistent with normal Windows service activity.

---

### 003 — Process Creation (Event ID 4688)

Enabled Windows Process Creation auditing and investigated real process creation events.

Covered:

- Enabling Process Creation auditing with `auditpol`
- Event ID 4688
- Process frequency analysis
- Process paths
- Account context
- Parent-child process relationships
- Splunk Universal Forwarder processes

Example relationships investigated:

```text
splunkd.exe → splunk-powershell.exe
services.exe → svchost.exe
svchost.exe → WmiPrvSE.exe
```

**Result:** The observed process activity and relationships were consistent with normal Windows activity and Splunk Universal Forwarder operation.

---

### 004 — Authentication Analysis (Event ID 4625)

Performed a broader authentication investigation using failed and successful logon events.

Covered:

- Multiple failed authentication events
- Authentication timing
- Account correlation
- Logon Type
- Status and sub-status codes
- Comparing failed and successful logons
- Identifying whether a rapid brute-force pattern was present

**Result:** The available evidence did not show a clear brute-force or external authentication attack.

## Example SPL Searches

### Find failed logons

```spl
index=main EventCode=4625
```

### Count failed logons by account

```spl
index=main EventCode=4625
| stats count by Account_Name
| sort - count
```

### Find process creation events

```spl
index=main EventCode=4688
```

### Count processes

```spl
index=main EventCode=4688
| stats count by New_Process_Name
| sort - count
```

### Investigate parent-child processes

```spl
index=main EventCode=4688
| table _time Account_Name Creator_Process_Name New_Process_Name Process_Command_Line
| sort _time
```

### Authentication summary

```spl
index=main (EventCode=4624 OR EventCode=4625)
| stats count by EventCode, Account_Name, Logon_Type
| sort - count
```

## SOC Investigation Method

The project follows a simple investigation workflow:

```text
Event
  ↓
Identify the event
  ↓
Collect relevant fields
  ↓
Check account and timestamp
  ↓
Check process/source/context
  ↓
Look for patterns
  ↓
Determine whether activity is normal or requires further investigation
  ↓
Document findings
```

A key lesson from this project is that an event or process should not automatically be considered malicious just because it appears in a security log.

## Evidence

Screenshots of Splunk searches and investigation results are included in the `Screenshots` folder.

Personal information should be removed or blurred before sharing screenshots publicly.

## Project Structure

```text
windows-splunk-soc-lab/
│
├── README.md
│
├── Investigations/
│   ├── 001-failed-logon-4625.md
│   ├── 002-successful-service-logon-4624.md
│   ├── 003-process-creation-4688.md
│   └── 004-authentication-analysis-4625.md
│
├── Screenshots/
│   ├── 001-...
│   ├── 002-...
│   ├── 003-...
│   └── 004-...
│
└── Splunk/
    └── useful-searches.md
```

## Learning Outcome

This project helped me gain practical experience with:

- Splunk Enterprise
- Splunk Universal Forwarder
- SPL
- Windows Event Logs
- Windows authentication events
- Process creation monitoring
- Parent-child process analysis
- Basic SOC investigation methodology
- Evidence-based incident assessment

## Future Improvements

Planned extensions include:

- Additional Windows security event investigations
- Detection rules and alerts in Splunk
- MITRE ATT&CK mapping based on observed behavior
- Additional endpoint telemetry
- Basic threat-hunting queries
- More authentication and process-based detections

## Disclaimer

This is a personal cybersecurity learning lab using my own Windows and Ubuntu virtualized environment. The investigations are intended for educational and defensive security monitoring purposes.
