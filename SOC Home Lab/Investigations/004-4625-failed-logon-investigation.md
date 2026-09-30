# Investigation 004 – Failed Logon Analysis (Event ID 4625)

## 1. Overview

**Investigation:** Failed Logon Analysis  
**Event ID:** 4625  
**Data Source:** Windows Security Logs  
**SIEM:** Splunk Enterprise  
**Time Range:** Last 7 days  
**Date:** 30 September 2026

### Objective

Investigate failed Windows authentication events and determine whether the activity shows a suspicious repeated-login or brute-force pattern.

## 2. Initial SPL Search

```spl
index=main EventCode=4625
```

The search identified 4 detailed Event ID 4625 events in the seven-day period.

## 3. Detailed Investigation

SPL used:

```spl
index=main EventCode=4625
| table _time Account_Name Logon_Type Failure_Reason Status Sub_Status Authentication_Package Workstation_Name Source_Network_Address
| sort _time
```

### Jnith – 3 events

- Logon Type: `2`
- Failure Reason: Unknown user name or bad password
- Status: `0xC000006D`
- Sub Status: `0xC000006A`
- Authentication Package: `Negotiate`
- Source Network Address: `-`

The events occurred on 28, 29, and 30 September 2026.

`0xC000006A` indicates an incorrect password. Logon Type 2 represents an interactive/local logon.

### NITHINKUMAR$ – 1 event

- Logon Type: `2`
- Status: `0xC000006D`
- Sub Status: `0xC0000380`
- Authentication Package: `Negotiate`
- Source Network Address: `127.0.0.1`

The source address is the local loopback address, indicating local activity.

## 4. Final SPL Summary

```spl
index=main EventCode=4625
| stats count by Account_Name, Logon_Type, Status, Sub_Status
| sort - count
```

Summary:

| Account      | Logon Type | Status       | Sub Status   | Count |
| ------------ | ---------: | ------------ | ------------ | ----: |
| Jnith        |          2 | `0xC000006D` | `0xC000006A` |     3 |
| NITHINKUMAR$ |          2 | `0xC000006D` | `0xC0000380` |     1 |

## 5. Comparison With Successful Logons

Successful 4624 events were also reviewed. Many were Logon Type 5 service logons involving accounts such as `NITHINKUMAR$` and `SYSTEM`.

The reviewed 4624 events were not directly following the 4625 failures in a short time window, so they were not treated as successful logons following the failed attempts.

## 6. Analysis

The three `Jnith` failures were spread across different days and were associated with incorrect passwords.

There was no rapid sequence such as:

```text
4625 → 4625 → 4625 → 4624
```

for the same account.

No remote source address was identified for the `Jnith` events.

The `NITHINKUMAR$` event showed a local source address (`127.0.0.1`).

## 7. Final Assessment

The observed Event ID 4625 activity is consistent with failed local authentication activity.

The available evidence does not show a clear brute-force pattern or evidence of an external authentication attack.

**SOC Disposition:** No suspicious activity identified from the available evidence.

## 8. Key Lessons Learned

- Event ID 4625 represents a failed logon.
- Logon Type 2 represents an interactive/local logon.
- `0xC000006A` indicates an incorrect password.
- Event frequency and timing are important when investigating possible brute-force activity.
- A failed logon should not automatically be treated as malicious.
- Successful and failed authentication events should be correlated by account and time.
- `stats`, `table`, and `sort` are useful SPL commands for authentication investigations.

## 9. Evidence

screenshots:

- Splunk detailed 4625 events.
- Splunk 4625 summary table.
- Optional screenshot of the 4624 comparison.
