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

### Part 1: Create Alert Rule For Potential Impossible Travel

Here I am setting up the rules to detect if there were any Potential Impossible Travel

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

<img width="1212" alt="image" src="Screenshot 2025-03-29 011637.png">

<img width="1212" alt="image" src="Screenshot 2025-03-29 012030.png">

---

### 2. Investigate the alert

After making the rule the alert was trigger and discovered that 52 accounts were set of.Here we observed 2 accounts one being josh.madakor@gmail.com  who had 4 instances in the last 7 but all logins were in the same state and city. And The other account arisa_lognpacific@lognpacific.com had 3 instances in 7 days somewhere different but were no more than a 1 hour distance from normal location.

**Query used to locate event:**

```kql
let TargetUserPrincipalName = "josh.madakor@gmail.com"; 
let TimePeriodThreshold = timespan(7d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

**Query used to locate event:**

```kql
let TargetUserPrincipalName = "arisa_lognpacific@lognpacific.com"; 
let TimePeriodThreshold = timespan(7d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```
<img width="1212" alt="image" src="Screenshot 2025-03-29 014525.png">

<img width="1212" alt="image" src="Screenshot 2025-03-29 014358.png">

<img width="1212" alt="image" src="Screenshot 2025-03-29 014648.png">

---

## Summary

MITRE ATT&CK - T1078: Valid Accounts

---

## Response Action

after investigating 52 alerts it was determined to be a TRUE Benign.The 52 accounts all had normal/relatively normal locations. so the accounts were left alone and to continue normal operations.(not disable)

---
