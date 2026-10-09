# Operation Ghost Handle

### SOC Investigation | Threat Hunting | Windows Event Log Analysis

**Scenario Date:** 9 October 2026
**Target Host:** WS-427
**Investigation Focus:** LSASS Credential Dumping, Suspicious Process Execution, and Credential Abuse

## 1. Executive Summary

Operation Ghost Handle is a scenario-based SOC investigation focused on suspicious activity involving workstation WS-427.

The scenario includes unusual process access to LSASS, suspicious process creation, possible dump-file creation, an endpoint detection alert, and failed logons followed by a successful privileged-account logon.

The objective is to investigate three hypotheses, correlate Windows event logs, identify possible credential exposure, and determine whether the activity indicates a genuine security incident.

**Evidence disclaimer:** This is a scenario-based investigation. The screenshots included below are illustrative Windows event-log references from external sources, not evidence collected from WS-427. No compromise is claimed without validating the original telemetry.

---

## 2. Hypothesis 1 — LSASS Credential Dumping

### Objective

Determine whether a suspicious process attempted to access LSASS memory to obtain credential material.

### Relevant Event

* **Sysmon Event ID 10:** Process Accessed

### Event Log Reference

### Fields to Investigate

* **SourceImage:** Identifies the process attempting to access LSASS.
* **TargetImage:** Check whether the target is `lsass.exe`.
* **GrantedAccess:** Shows the requested access rights.
* **CallTrace:** May help identify suspicious modules involved in the access.

### Investigation Approach

Correlate Event ID 10 with process-creation events, endpoint detection alerts, and any suspicious dump-file creation. Determine whether the source process is an approved security tool or an unexpected executable.

### False-Positive Analysis

Antivirus, EDR, debugging, and diagnostic tools may legitimately access LSASS. An Event ID 10 record alone does not prove that credentials were extracted.

**Current Assessment:** Unconfirmed. Original WS-427 telemetry is required.

---

## 3. Hypothesis 2 — Suspicious Signed-Binary Execution

### Objective

Determine whether a legitimate or digitally signed executable was used in an unusual way to launch commands, execute another process, or support credential access.

### Relevant Event

* **Windows Security Event ID 4688:** A New Process Has Been Created
*


### Fields to Investigate

* **New Process Name:** Identifies the executable that was launched.
* **Creator Process Name:** Identifies the parent process when available.
* **Process Command Line:** Shows the command and arguments when command-line auditing is enabled.
* **Process ID and timestamp:** Help correlate execution with other events.

### Investigation Approach

Review the executable's path, signature, hash, command-line arguments, and parent-child process relationship. Correlate suspicious execution with LSASS access and endpoint detection alerts.

A valid digital signature does not automatically mean that a process is safe. However, a signed executable running on a system is not inherently malicious.

### False-Positive Analysis

Installers, administrative scripts, system utilities, and endpoint-management tools can generate unusual process chains.

**Current Assessment:** Unconfirmed. Process-chain analysis and file validation are required.

---

## 4. Hypothesis 3 — Credential Abuse and Lateral Movement

### Objective

Determine whether failed authentication attempts were followed by an unexpected successful logon, potentially involving a privileged account or remote session.

### Relevant Events

* **Windows Security Event ID 4624:** Successful Logon
* **Windows Security Event ID 4625:** Failed Logon

### Event Log Reference


### Fields to Investigate

* **Logon Type:** Type 10 typically indicates a RemoteInteractive logon, commonly associated with Remote Desktop.
* **TargetUserName:** Identifies the account involved.
* **IpAddress:** Helps identify the source address when present.
* **Logon ID:** Helps correlate related events within a session.

### Investigation Approach

Build a timeline of failed logons and subsequent successful logons. Validate the account's privileges, source address, expected activity, and any subsequent remote process execution. Correlate endpoint logs with relevant authentication records from domain controllers.

### False-Positive Analysis

Mistyped passwords, VPN changes, approved remote support, and legitimate administrative sessions can produce similar activity. A successful logon following failed attempts does not independently prove credential abuse or lateral movement.

**Current Assessment:** Unconfirmed. Account context, source address, and correlated activity must be validated.

---

## 5. Supporting Evidence — Suspicious File Creation

Investigate any suspicious `.dmp` file created in a user-writable directory. Review the filename, full path, creating process, timestamp, and available file hash.

A dump file alone does not prove that LSASS memory was captured. Its origin and relationship to other events must be established.

---

## 6. Evidence Correlation Timeline

| Event              | Investigation Purpose                               |
| ------------------ | --------------------------------------------------- |
| Event ID 4625      | Identify failed authentication attempts             |
| Event ID 4688      | Identify suspicious process creation                |
| Sysmon Event ID 10 | Investigate access to LSASS                         |
| Sysmon Event ID 11 | Investigate suspicious file creation                |
| Event ID 4624      | Validate successful logons and session context      |
| EDR alert          | Correlate endpoint detection with Windows telemetry |

Actual timestamps and event ordering must be obtained from the original logs before establishing the final timeline.

---

## 7. Detection Logic and False-Positive Analysis

Prioritize investigation when multiple independent signals align, such as suspicious LSASS access, unusual process execution, a related dump file, and abnormal privileged authentication.

Detection improvements should include:

* Correlating process access with process-creation events.
* Reviewing executable paths, signatures, and parent-child relationships.
* Monitoring unusual privileged logons and remote sessions.
* Tuning detections to reduce noise from approved administrative and security tools.
* Verifying endpoint logging coverage and investigating unexpected gaps.

No single event should be treated as definitive proof of compromise without supporting evidence.

---

## 8. Identity and Persistence Investigation

Review relevant telemetry for:

* Unexpected privileged-account use.
* Unauthorized remote sessions.
* New user accounts or privilege changes.
* Suspicious scheduled tasks and services.
* Unusual registry or WMI persistence activity.

Relevant Windows Security events include Event ID 4672 for special privileges assigned to a logon, Event ID 4698 for scheduled-task creation, and Event ID 4720 for user-account creation.

These are investigation leads, not confirmed findings for WS-427.

---

## 9. Incident Assessment and Closure

**Current Disposition:** Investigation required; compromise not confirmed.

Before closing the investigation:

1. Validate all three hypotheses using original endpoint, EDR, and identity telemetry.
2. Establish a timestamped event sequence.
3. Determine whether credentials or privileged sessions were exposed.
4. Document false positives, evidence gaps, and response actions.
5. Preserve relevant logs and artifacts according to the incident-response process.

### Closure Criteria

Close the case as a confirmed incident only when the evidence supports malicious activity and the response actions are documented. If the available telemetry is insufficient, record the unresolved questions and visibility gaps rather than claiming the endpoint is clean.

---

## 10. Key Takeaways

* LSASS access should be investigated in context, not treated as automatic proof of credential theft.
* Signed executables can be abused, so process behavior and execution context matter.
* Failed logons followed by successful logons warrant correlation, especially for privileged accounts.
* Multiple independent indicators provide stronger evidence than isolated events.
* Accurate incident reporting must distinguish observed evidence from hypotheses.

**Project Type:** Scenario-based SOC investigation and Windows event-log analysis
**Tools and Telemetry Referenced:** Windows Security logs, Sysmon, EDR alerts, process telemetry, authentication records
