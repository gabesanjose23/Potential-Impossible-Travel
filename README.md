# Potential Impossible Travel



## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft Sentinel

##  Scenario

Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as Invoke-WebRequest, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.  

---

## Steps Taken

### Part 1: Create Alert Rule PowerShell Suspicious Web Request

Here I am setting up the rules to detect if there were any Suspicious PowerShell running. 

```kql
let TimePeriodThreshold = timespan(7d); 
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

<img width="1212" alt="image" src="Screenshot 2025-03-26 004914.png">

<img width="1212" alt="image" src="Screenshot 2025-03-26 005151.png">

---

### 2. Investigate the alert

The Suspicious Web Request was triggered on 1 device by 1 user,but download 4 different scripts.After investigating with Defender for Endpoint, it was determined that the downloaded scripts did run.see the following query.

**Query used to locate event:**

```kql
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
<img width="1212" alt="image" src="Screenshot 2025-03-26 013922.png">

<img width="1212" alt="image" src="Screenshot 2025-03-26 013220.png">

---

## Summary

MITRE ATT&CK - T1078: Valid Accounts

MITRE ATT&CK - T1059.001: PowerShell

MITRE ATT&CK - T1105: Ingress Tool Transfer

MITRE ATT&CK - T1203: Exploitation for Client Execution

MITRE ATT&CK - T1041: Exfiltration Over C2 Channel

---

## Response Action

Machine was isolated in MDE and an anti-malware scan was run.After the machine came back clean, we removed it from isolation, had the affected user go through extra rounds of cybersecurity awareness training and upgraded our training package from  knowBe4 and increased frequency.Started the implementation of a policy that restricts the use of powershell for non-essential users.

---
