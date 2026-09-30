# Investigation 002 — Successful Service Logon (Windows Event ID 4624)

## 1. Investigation Overview

**Date:** 29 September 2026  
**Platform:** Windows Host + Splunk Enterprise on Ubuntu  
**Data Source:** Windows Security Event Log  
**Event ID:** 4624 — An account was successfully logged on  
**Investigation Type:** Authentication / Service Logon

## 2. Objective

Investigate successful Windows logon events and determine what type of authentication activity they represent.

## 3. Splunk Search

```spl
index=main EventCode=4624 Logon_Type=5
| stats count by Account_Name, Account_Domain, Process_Name
| sort - count
```

## 4. Observations

Four Event ID 4624 events were observed in the final investigation search.

- Logon Type: 5
- Authentication Package: Negotiate
- Process: `C:\Windows\System32\services.exe`
- Account domains observed: `WORKGROUP` and `NT AUTHORITY`
- Domain distribution: 2 events associated with `WORKGROUP` and 2 with `NT AUTHORITY`

## 5. Analysis

Event ID 4624 indicates a successful logon.

Logon Type 5 represents a service logon. This means the event is associated with a Windows service rather than a normal interactive desktop sign-in.

The process `C:\Windows\System32\services.exe` is the Windows Service Control Manager, which manages Windows services.

`NT AUTHORITY` is a normal Windows security authority. `WORKGROUP` is the local workgroup context on a non-domain Windows system.

The authentication package `Negotiate` is a normal Windows authentication mechanism.

## 6. Assessment

The observed events are consistent with normal Windows service authentication activity.

The presence of multiple successful Type 5 logons does not by itself indicate malicious activity. The process, logon type, and account-domain context provide reasonable evidence that these events are related to Windows service activity.

No suspicious behavior was identified from these events alone.

## 7. SOC Disposition

**Disposition:** Informational / No escalation based on current evidence.

No containment action was taken.

## 8. Lessons Learned

This investigation demonstrated that a successful logon event is not necessarily an interactive user login.

Important fields used:

- Event ID
- Logon Type
- Account Name
- Account Domain
- Authentication Package
- Process Name

## 9. Evidence

**Splunk evidence:** Screenshot of the final Event ID 4624 Type 5 search.
file-name:
002-4624-service-logon.png

```

```
