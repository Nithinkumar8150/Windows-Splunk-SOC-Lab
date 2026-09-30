Investigation 001 — Failed Logon (Windows Event ID 4625)

1. Investigation Overview

Date: 29 September 2026
Platform: Windows Host + Splunk Enterprise on Ubuntu
Data Source: Windows Security Event Log
Event ID: 4625 — An account failed to log on
Investigation Type: Authentication / Failed Logon

2. Objective

Investigate failed Windows logon events collected from the Windows host by the Splunk Universal Forwarder and determine whether the activity appears suspicious.

3. Splunk Search

Initial search:

index=main EventCode=4625

Investigation search:

index=main EventCode=4625
| table \_time Account_Name Logon_Type Failure_Reason Status Sub_Status Authentication_Package Workstation_Name Source_Network_Address

4. Observations

Two Event ID 4625 events were observed.

Both events were associated with the same account.

Observed fields

Field

Observed value

Event ID

4625

Logon Type

2

Authentication Package

Negotiate

Status

0xC000006D

Sub Status

0xC000006A

Source Network Address

Blank

Number of events observed

2

Account

Same account in both events

5. Event Analysis

Event ID 4625 indicates that a logon attempt failed.

Logon Type 2 represents an interactive logon, meaning the authentication attempt was associated with a local interactive sign-in rather than a typical network logon.

The Negotiate authentication package is a normal Windows authentication mechanism.

The Sub Status 0xC000006A indicates that the supplied password was incorrect.

The Source Network Address was blank in both events, so these events did not provide a remote source IP address for investigation.

6. Assessment

The two failed logon events are consistent with incorrect-password attempts during local/interactive authentication.

Based on the evidence available in these events, there is not enough evidence to classify the activity as a brute-force attack or other malicious activity.

The low number of events and lack of a remote source address reduce the amount of evidence suggesting a network-based attack.

7. SOC Disposition

Disposition: Informational / No escalation based on current evidence.

No containment action was taken.

Continue monitoring for:

Repeated failed logons

A high number of 4625 events

Failed logons followed by a successful 4624 event

Remote source IP addresses

Multiple accounts targeted from the same source

Other suspicious authentication or process events

8. Lessons Learned

This investigation demonstrated the importance of investigating the context of an alert instead of treating every failed login as malicious.

The investigation used:

Splunk

SPL

Windows Security Event Logs

Event ID 4625

Authentication event analysis

Logon Type analysis

Windows status/sub-status interpretation

Basic SOC alert triage

9. Evidence

Splunk evidence: Screenshot of the Event ID 4625 search/result

001-4625-search.png
