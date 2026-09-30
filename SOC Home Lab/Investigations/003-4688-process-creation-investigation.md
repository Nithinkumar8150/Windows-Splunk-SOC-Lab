# Investigation 003 – Windows Process Creation (Event ID 4688)

## 1. Overview

**Investigation:** Windows Process Creation  
**Event ID:** 4688  
**Data Source:** Windows Security Logs  
**SIEM:** Splunk Enterprise  
**Forwarder:** Splunk Universal Forwarder  
**Date:** 30 September 2026

### Objective

Enable Windows process-creation auditing, collect Event ID 4688 in Splunk, and investigate normal process activity and parent-child process relationships.

---

## 2. Enabling Windows Process Creation Auditing

Initially, Event ID 4688 was not appearing in Splunk.

Process Creation auditing was enabled from an **Administrator Command Prompt**:

```cmd
auditpol /set /subcategory:"Process Creation" /success:enable
```

This enables Windows to record successful process-creation events.

The setting was verified with:

```cmd
auditpol /get /subcategory:"Process Creation"
```

The result showed **Success** enabled.

A harmless `notepad.exe` process was then started to generate a test 4688 event.

---

## 3. Confirming Event 4688

Event ID **4688** was confirmed in:

**Event Viewer → Windows Logs → Security**

The event was then received by Splunk through the Splunk Universal Forwarder.

Splunk search:

```spl
index=main EventCode=4688
```

The search returned process-creation events.

---

## 4. Process Frequency Investigation

SPL used:

```spl
index=main EventCode=4688
| stats count by New_Process_Name
| sort - count
```

Some observed processes included:

- `splunk-powershell.exe` – 30
- `splunk-MonitorNoHandle.exe` – 15
- `splunk-admon.exe` – 15
- `splunk-netmon.exe` – 15
- `splunk-regmon.exe` – 15
- `chrome.exe` – 9
- `svchost.exe` – 9
- `WmiPrvSE.exe` – 7
- `backgroundTaskHost.exe` – 3

### Observation

The high number of Splunk processes was related to the installed Splunk Universal Forwarder. Chrome and normal Windows processes were also observed.

A process name alone was not treated as suspicious.

---

## 5. Splunk Process Investigation

The frequently appearing Splunk PowerShell process was investigated.

SPL used:

```spl
index=main EventCode=4688 New_Process_Name="*splunk-powershell.exe*"
| table _time Account_Name New_Process_Name Creator_Process_Name Process_Command_Line
```

Observed:

- **Account:** `SplunkForwarder`
- **New Process:** `C:\Program Files\SplunkUniversalForwarderin\splunk-powershell.exe`
- **Creator Process:** `C:\Program Files\SplunkUniversalForwarderin\splunkd.exe`
- **Command Line:** Blank in the collected event

The events appeared at regular intervals.

### Assessment

The activity was consistent with normal Splunk Universal Forwarder activity. The process was running under the `SplunkForwarder` account and was created by `splunkd.exe`.

No suspicious behavior was identified from these events.

---

## 6. Parent-Child Process Investigation

SPL used:

```spl
index=main EventCode=4688
| table _time Account_Name Creator_Process_Name New_Process_Name Process_Command_Line
| sort _time
```

Observed relationships included:

```text
splunkd.exe → splunk-powershell.exe
splunkd.exe → splunk-admon.exe
splunkd.exe → splunk-netmon.exe
splunkd.exe → splunk-regmon.exe
services.exe → svchost.exe
svchost.exe → WmiPrvSE.exe
svchost.exe → RuntimeBroker.exe
svchost.exe → backgroundTaskHost.exe
```

### Assessment

The observed parent-child relationships were consistent with normal Windows activity and the installed Splunk Universal Forwarder.

`WmiPrvSE.exe` was noted because WMI can be abused by attackers, but its presence alone does not indicate malicious activity.

---

## 7. Final Assessment

**Event:** 4688 – Process Creation

The investigation demonstrated how Windows process creation events can be collected and investigated in Splunk.

The observed processes and parent-child relationships were consistent with normal system activity and Splunk Universal Forwarder activity.

**SOC Disposition:** No suspicious activity identified from the available evidence.

---

## 8. Key Lessons Learned

- Event ID 4688 records successful process creation when auditing is enabled.
- Windows audit policies can be configured and checked using `auditpol`.
- A process name alone is not enough to determine whether activity is malicious.
- Parent-child process relationships provide important investigation context.
- Process frequency can help identify unusual or high-volume activity.
- Splunk `stats`, `sort`, and `table` are useful for basic SOC investigations.
- MITRE ATT&CK should not be mapped directly from an event ID; the observed behavior should be understood first.

## 9. Evidence

screenshots:

- Windows Event Viewer showing Event ID 4688.
- Splunk process-frequency results.
- Splunk parent-child process results.
