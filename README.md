# Operation Overreach — Complete Threat Hunt Report

> **Case:** GF-INC-2026-0806  
> **Organisation:** Greenfield Logistics  
> **Hunt:** Hunt 13 / Operation Overreach  
> **Platform:** Hybrid Entra ID + on-prem AD  
> **Evidence window:** 5–6 August 2026

## Source Basis

This report is compiled from the supplied Claude transcript (`operation-overreach-ctf-threat-hunt.pdf`) and `Flags(2).docx`. The PDF is used for the exact challenge-question wording wherever that wording is present; `Flags(2).docx` is treated as the authoritative source for each Flag Data Block. All source values are preserved without redaction.

## Scenario (Bigger Picture)

Greenfield Logistics is investigating a post-compromise intrusion across a hybrid Microsoft environment. The hunt begins with a correlated cloud incident involving a Finance user account, but the challenge explicitly warns that the visible sign-in noise is not the whole story. The investigation reconstructs the intrusion from the earliest identity telemetry through cloud collection, mailbox persistence, automated directory discovery, VPN access, on-prem reconnaissance, AI-agent abuse, certificate-based privilege escalation, DCSync, durable AD persistence, sensitive-file collection, and response/containment.

The evidence spans two Log Analytics workspaces. **LAW-Cyber-Range** contains cloud/Entra/M365/Graph/MDI/MDE telemetry; **LAW-SilentCorridor** contains on-prem AD, Linux/VPN, Windows object access, certificate services, directory changes, and the custom agent/MCP telemetry. The hunt explicitly states that both workspaces are shared/contaminated, so queries must be bound to the 5–6 August 2026 window and to the identities under investigation. fileciteturn1file8L455-L481

## What I Have to Do / Identify

- Establish the true start of attacker activity rather than anchoring only on product detection time.
- Distinguish attacker activity from shared-egress traffic, routine infrastructure activity, false positives, and scheduled/background operations.
- Reconstruct the cloud phase: session use, file discovery/collection, credential recovery, mailbox persistence, automated risk decisions, and Graph/ARM reconnaissance.
- Prove the cloud-to-on-prem pivot, including VPN authentication, TOTP seed recovery, translated internal reconnaissance, and the identity behind file collection.
- Reconstruct the AI-agent confused-deputy chain and correlate ticket content, gate decisions, MCP execution, and the resulting AD reset.
- Prove the privilege-escalation chain: certificate enrollment, Authentication Mechanism Assurance, Tier-0 group membership, DCSync, and surviving ACL persistence.
- Identify disclosure/breach-impacting collection and convert the evidence into response, containment, detection, and credential-rotation decisions.

## Tools and Technologies

| Tool / technology | Role in the hunt |
|---|---|
| Microsoft Defender XDR / Defender for Identity | Alerts, identity telemetry, correlated incidents, discovery detections |
| Microsoft Sentinel / Log Analytics | SecurityAlert / SecurityIncident correlation and KQL investigation |
| KQL / Advanced Hunting | Primary query and correlation language |
| LAW-Cyber-Range | Entra ID, M365, Graph, MDI/MDE, risk, URL, mailbox, incident and network-flow telemetry |
| LAW-SilentCorridor | Windows security, account management, certificate services, object access, directory changes, Linux/VPN, agent/MCP telemetry |
| IdentityLogonEvents / SigninLogs / AADNonInteractiveUserSignInLogs | Identity and token activity |
| UrlClickEvents / CloudAppEvents / OfficeActivity | Mail/file pivots, file restore, mailbox and forwarding activity |
| MicrosoftGraphActivityLogs / NTANetAnalytics | Directory enumeration and internal reconnaissance |
| AuditLogs / AADUserRiskEvents | Persistence checks and automated risk decisions |
| SecurityEvent / WindowsAccountMgmt_CL / WindowsCertServices_CL / WindowsDirChanges_CL | AD privilege changes, resets, certificates, replication rights, ACL changes |
| WindowsObjectAccess_CL | File/share/named-pipe access |
| LLMAgentLogs_CL / MCPToolCalls_CL | AI-agent decision, authorization, and tool execution chain |
| LinuxAuth_CL | OpenVPN and PAM/TOTP authentication evidence |

## Flag-by-Flag Investigation

> **Flag Data Block:** taken from `Flags(2).docx`; `QUERY: N/A` is retained where the source says no query is required. The transcript identifies T1, T2, S3 and IR1–IR10 as the N/A-query group. fileciteturn1file0L22-L39

### Flag 1 — T1 - The Entry Alert

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

![Flag 1 evidence](assets/1.png)

#### Flag Data Block

> **FLAG**
> Possible use of a stolen session cookie

**TIME (UTC):** 2026-08-05 19:04:50 UTC

**EVENT:** Possible use of a stolen session cookie where user m.smith (user) was impacted.

**SOURCE:** Microsoft Defender for Identity

**QUERY:**
`N/A`

#### Findings

The initiating alert was the stolen-session-cookie detection on m.smith. Later telemetry places the first witnessed identity action earlier than this product alert.

### Flag 2 — T2 - The Second High

#### Flag Scenario

Later the same evening, same product, another High. This one is not about how they signed in, it is about something the account is actively doing. It fired at 20:08:56. If I can name the phase this belongs to, I know where to look next. Which phase does it evidence? Format: tactic or phase name View Hint Not sign-in risk, behaviour. Read what the product observed the account doing. Unlock Hint for 50 points

![Flag 2 evidence](assets/2.png)

#### Flag Data Block

> **FLAG**
> Discovery

**TIME (UTC):** 2026-08-05 19:04:50 UTC

**EVENT:** A possibly compromised user account signed in. An automated tool used for discovery     successfully logged into a user account, indicating that the user account's credentials might have been leaked or are in the possession of an unauthorized party.

 SOURCE: Microsoft Defender for Identity

**SOURCE:** Microsoft Defender for Identity

**QUERY:**
`N/A`

#### Findings

The second High was behavioral discovery activity, establishing reconnaissance rather than another sign-in symptom.

### Flag 3 — T3 - The False Positive

#### Flag Scenario

Two Highs fired on-prem and I am not taking either at face value. One lines up with the attack. The other fires as the DC is coming up and points at nothing I can tie to a beat. Before I chase both I want the one I can close. Which is the false positive? Format: alert title View Hint Look in SecurityAlert in LAW-SilentCorridor (on-prem workspace). Filter to High severity.  Compare each alert's StartTime against the reset at 11:53:55. One predates it - the DC was still starting up when it fired. That one has nothing to do with the attack. Unlock Hint for 50 points 6/100 attempts OPERATION OVERREACHPRACTICE LIVEHunt 13 // 00 - Triage LIVEHunt 13 // 01 - Initial Access LIVEHunt 13 // 02 - Collection LIVEHunt 13 // 03 - Persistence & Evasion LIVEHunt 13 // 04 - Escalation CYBER RANGE//0x48554E54 T4 - The Unactioned Window 141 The cloud incident escalates High on the evening of the 5th. The first on-prem action I can see is the next morning. Nothing across that stretch is witnessed by an analyst, so it is the part I rebuild from evidence alone. I want its length before I start. How long is it? Format: duration (e.g. 15h55m) View Hint The incident went High, then the trail goes quiet. Measure from that to the first on-prem action. View Hint

![Flag 3 evidence](assets/3.png)

#### Flag Data Block

> **FLAG**
> GF Pipe - Post-Exploitation Framework Named Pipe

**TIME (UTC):** 2026-08-05T03:23:11.7012421Z

**EVENT:** The false positive

**SOURCE:** LAW-SilentCorridor / SecurityAlert

**QUERY:**
```kql
SecurityAlert
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where AlertSeverity == "High"
| project TimeGenerated, AlertName, AlertSeverity, Description, CompromisedEntity, ExtendedProperties
| order by TimeGenerated asc
```

#### Findings

The 03:23:11.7012421Z GF Pipe alert was the false-positive instance. Severity alone was not enough; timeline correlation closed it.

### Flag 4 — T4 - The Unactioned Window

#### Flag Scenario

The cloud incident escalates High on the evening of the 5th. The first on-prem action I can see is the next morning. Nothing across that stretch is witnessed by an analyst, so it is the part I rebuild from evidence alone. I want its length before I start. How long is it? Format: duration (e.g. 15h55m) View Hint The incident went High, then the trail goes quiet. Measure from that to the first on-prem action. View Hint

![Flag 4 evidence](assets/4.png)

#### Flag Data Block

> **FLAG**
> 15h55m

**TIME (UTC):** Start/end timestamps not conclusively established from the retrieved telemetry; duration confirmed as 15h55m by the challenge.

**EVENT:** Correlated incident escalated to High → first attacker action inside the estate (VPN authentication).

**SOURCE:** SecurityIncident (LAW-Cyber-Range)  LinuxAuth_CL (LAW-SilentCorridor)

EVENT/RECORD ID: Target incident escalation and first attacker VPN record not conclusively identified.

**QUERY:**
```kql
SecurityIncident
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| order by TimeGenerated asc

LinuxAuth_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where EventProduct == "OpenVPN"
| where EventType == "Logon"
| where EventResult == "Success"
| order by TimeGenerated asc
```

#### Findings

The challenge fixes a 15h55m unactioned window between cloud escalation and first attacker action inside the estate; the supplied block does not conclusively identify both bookends.

### Flag 5 — C1 - First Contact

#### Flag Scenario

Flag 5 (overall) TIME (UTC): 2026-08-05 18:44:47.748 EVENT: Earliest witnessed action by the compromised identity - a failed interactive sign-in attempt from IP 159.26.115.80, rejected at the MFA stage ("Strong Authentication is required"). This precedes the Entra/SigninLogs record and the MDI "stolen session cookie" alert (19:04:50) by ~20 minutes, establishing the true start of attacker activity rather than the product's later detection point. SOURCE: Microsoft Defender for Identity - IdentityLogonEvents (LAW-Cyber-Range) QUERY: IdentityLogonEvents | where TimeGenerated between (datetime(2026-08-05T00:00:00Z) .. datetime(2026-08-05T19:04:50Z)) | where AccountUpn has "m.smith" or AccountName has "m.smith" | order by TimeGenerated asc  | project TimeStr = format_datetime(TimeGenerated, 'HH:mm:ss.fff'), ActionType, LogonType, Protocol, FailureReason, IPAddress, DeviceName, Application Want to keep going on Stage 01 from here - following that IP/session forward to the successful sign-in and cookie theft?

![Flag 5 evidence](assets/5.png)

#### Flag Data Block

> **FLAG**
> 18:44:47.748

**TIME (UTC):** 2026-08-05T18:44:47.748Z

**EVENT:** Earliest witnessed action by the compromised identity — a failed interactive sign-in attempt from IP 159.26.115.80, rejected at the MFA stage ("Strong Authentication is required"). This precedes the Entra/SigninLogs record and the MDI "stolen session cookie" alert (19:04:50) by ~20 minutes, establishing the true start of attacker activity rather than the product's later detection point.

**SOURCE:** LAW-Cyber-Range / IdentityLogonEvents

**QUERY:**
```kql
IdentityLogonEvents
| where TimeGenerated between (datetime(2026-08-05T00:00:00Z) .. datetime(2026-08-05T19:04:50Z))
| where AccountUpn has "m.smith" or AccountName has "m.smith"
| order by TimeGenerated asc
| project TimeStr = format_datetime(TimeGenerated, 'HH:mm:ss.fff'), ActionType, LogonType, Protocol, FailureReason, IPAddress, DeviceName, Application
```

#### Findings

18:44:47.748Z is the earliest witnessed compromised-identity activity, predating the stolen-session alert and anchoring the true start of the timeline.

### Flag 6 — C2 - The Other Identity

#### Flag Scenario

155 Before I scope this to the attacker's address I check who else is on it. There is a second identity on the same address in the same window. If I scope on the address without checking, I drag them in. Who is the other account, and what does that do to how I scope? Format: account name and scoping decision Unlock Hint for 0 points Enumerate every identity on that address before scoping to it. One of them is not the attacker. Unlock Hint for 50 points The other is on all four exits and sits in a different domain from the attacker's. Name it, and say what you scope by instead. Tactic: scoping discipline. 0/50 attempts

#### Flag Data Block

> **FLAG**
> mohammed_admin@lognpacific.com — scope by account/session identity

**TIME (UTC):** 2026-08-05T19:59:45.933Z – 2026-08-05T21:11:14.420Z

**EVENT:** The same IP (159.26.115.80) also carries non-interactive Azure CLI traffic from mohammed_admin@lognpacific.com — a different domain (.com vs m.smith's .org) and a different application pattern than the attacker's interactive browser/Outlook/Teams activity. The address is shared egress infrastructure, not an attacker fingerprint, so scoping the hunt to it directly would have pulled an unrelated identity into the investigation. Scope by account/session instead of source IP.

**SOURCE:** LAW-Cyber-Range / AADNonInteractiveUserSignInLogs

**QUERY:**
```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(2026-08-05T00:00:00Z) .. datetime(2026-08-06T00:00:00Z))
| where IPAddress == "159.26.115.80"
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Count=count() by UserPrincipalName, AppDisplayName, ResultType
| order by FirstSeen asc
x=6
```

#### Findings

The source IP is shared with mohammed_admin@lognpacific.com, so the investigation must scope to account/session identity rather than IP alone.

### Flag 7 — C3 - The Pivot Record

#### Flag Scenario

150 The session is working the mailbox, then it is acting on a file in cloud storage. No search in between, so something it read pointed it there. There should be a record that carries it across. Which record? Format: filename View Hint Something it read pointed it there. Look between the last mail action and the first file action. View Hint A click record bridges them, and its workload tells you which side it came from. Pivot to UrlClickEvents. Tactic: Collection.

![Flag 7 evidence](assets/7.png)

#### Flag Data Block

> **FLAG**
> Invoice_Reconciliation_Q3.xlsx

**TIME (UTC):** 2026-08-05T18:59:27.3709105Z

**EVENT:** A Safe Links-scanned URL click bridges the mailbox and the cloud file: the record's Workload is Email (mail-sourced), pointing to Invoice_Reconciliation_Q3.xlsx hosted on an external tenant (joshmadakorgmail-my.sharepoint.com), not Greenfield's own SharePoint. No search precedes the file access — this click is the only thing that explains how the session got there, and it also flags the file as living outside the org's own storage.

**SOURCE:** LAW-Cyber-Range / UrlClickEvents

**QUERY:**
```kql
UrlClickEvents
| where Timestamp between (datetime(2026-08-05T18:44:47Z) .. datetime(2026-08-06T00:00:00Z))
| where AccountUpn has "m.smith"
| order by Timestamp asc
| project Timestamp, Url, ActionType, IsClickedThrough, Workload, NetworkMessageId
```

#### Findings

The Safe Links click is the bridge from mailbox activity to Invoice_Reconciliation_Q3.xlsx on an external SharePoint tenant.

### Flag 8 — C4 - The Restore

#### Flag Scenario

Flag (number overall): [confirm once accepted] TIME (UTC): 2026-08-05T19:05:59Z EVENT: Amid an otherwise one-directional burst of reads and downloads, one action reverses direction - Personal.kdbx, a KeePass password database, is restored (not read or taken) in m_smith's personal OneDrive vault. Restoring rather than simply accessing an existing file implies the attacker needed a prior version of the vault back - consistent with recovering credentials that had since been changed, deleted, or overwritten, rather than just harvesting what was already sitting there. SOURCE: LAW-Cyber-Range / CloudAppEvents QUERY: CloudAppEvents | where Timestamp between (datetime(2026-08-05T18:59:27Z) .. datetime(2026-08-06T00:00:00Z)) | where AccountDisplayName == "Mark Smith" | where ActionType == "FileRestored" Ready for the next one whenever you are. You C5 - The Bridge File 162 Most of what they took are password stores. One file is not, and it is the one that makes anything on-prem possible. Which file? Format: filename Unlock Hint for 0 points Separate the vaults from the rest of the haul. One file is a bridge, not a store. Unlock Hint for 50 points Read the FileAccessed set and look at the path it sits under. Tactic: Credential Access, downstream. 9/50 attempts OfficeActivity | where TimeGenerated between (datetime(2026-08-05T18:59:27Z) .. datetime(2026-08-06T00:00:00Z)) | where isnotempty(OfficeObjectId) | where UserId == "m.smith@lognpacific.org" | where Operation contains "Access" | project-reorder TimeGenerated, UserAgent, Operation, OfficeObjectId, * Correct flag: 8/5/2026, 7:04:17.000 PM Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 FileAccessed https://joshmadakorgmail-my.sharepoint.com/personal/m_smith_lognpacific_org/Documents/IT-Cred entials/VPN-Access-Credentials.txt

![Flag 8 evidence](assets/8.png)

#### Flag Data Block

> **FLAG**
> https://joshmadakorgmail-my.sharepoint.com/personal/m_smith_lognpacific_org/Documents/Personal.kdbx, FileRestored

**TIME (UTC):** 2026-08-05T19:05:59Z

**EVENT:** Amid an otherwise one-directional burst of reads and downloads, one action reverses direction — Personal.kdbx, a KeePass password database, is restored (not read or taken) in m_smith's personal OneDrive vault. Restoring rather than simply accessing an existing file implies the attacker needed a prior version of the vault back — consistent with recovering credentials that had since been changed, deleted, or overwritten, rather than just harvesting what was already sitting there.

**SOURCE:** LAW-Cyber-Range / CloudAppEvents

**QUERY:**
```kql
CloudAppEvents
| where Timestamp between (datetime(2026-08-05T18:59:27Z) .. datetime(2026-08-06T00:00:00Z))
| where AccountDisplayName == "Mark Smith"
| where ActionType == "FileRestored"
```

#### Findings

Personal.kdbx was restored, not simply read. That supports recovery of an earlier vault version as a credential-collection action.

### Flag 9 — C5 - The Bridge File

#### Flag Scenario

162 Most of what they took are password stores. One file is not, and it is the one that makes anything on-prem possible. Which file? Format: filename Unlock Hint for 0 points Separate the vaults from the rest of the haul. One file is a bridge, not a store. Unlock Hint for 50 points Read the FileAccessed set and look at the path it sits under. Tactic: Credential Access, downstream. 9/50 attempts OfficeActivity | where TimeGenerated between (datetime(2026-08-05T18:59:27Z) .. datetime(2026-08-06T00:00:00Z)) | where isnotempty(OfficeObjectId) | where UserId == "m.smith@lognpacific.org" | where Operation contains "Access" | project-reorder TimeGenerated, UserAgent, Operation, OfficeObjectId, * Correct flag: 8/5/2026, 7:04:17.000 PM Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 FileAccessed https://joshmadakorgmail-my.sharepoint.com/personal/m_smith_lognpacific_org/Documents/IT-Cred entials/VPN-Access-Credentials.txt

![Flag 9 evidence](assets/9.png)

#### Flag Data Block

> **FLAG**
> VPN-Access-Credentials.txt

**TIME (UTC):** 2026-08-05T19:04:17.000Z

**EVENT:** Among a haul otherwise made up of password/credential stores (KeePass vaults, Invoice_Reconciliation, etc.), one file stands apart — VPN-Access-Credentials.txt, sitting under an IT-Credentials folder in m_smith's personal OneDrive. Unlike the vault files, this one isn't a store to crack open later — it's plaintext access material for the on-prem VPN, meaning it's the piece that actually converts a cloud account compromise into a foothold inside the on-prem estate. This is the bridge between the cloud phase and everything that follows on-prem.

**SOURCE:** LAW-Cyber-Range / OfficeActivity

**QUERY:**
```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-08-05T18:59:27Z) .. datetime(2026-08-06T00:00:00Z))
| where isnotempty(OfficeObjectId)
| where UserId == "m.smith@lognpacific.org"
| where Operation contains "Access"
| project-reorder TimeGenerated, UserAgent, Operation, OfficeObjectId, *
```

#### Findings

VPN-Access-Credentials.txt is the cloud-to-on-prem bridge because it exposes the material needed for VPN access.

### Flag 10 — C6 - The Hidden Forward

#### Flag Scenario

160 Mail is leaving a mailbox the user never set a forward on. What operation actually set it, as the log names it? Format: operation name View Hint Check the inbox-rule tables first. When they come back clean, ask where else forwarding can be set. View Hint It was set on the mailbox object, which is a different operation with a different shape, so a rule hunt misses it. Find it in OfficeActivity/CloudAppEvents. Tactic: Persistence. 5/50 attempts Correct Correct Flag: Set-Mailbox 8/5/2026, 7:45:07.000 PM ExchangeAdmin Set-Mailbox 939e93f3-04f6-479d-82ff-345c231abb4d 939e93f3-04f6-479d-82ff-345c231abb4d Admin m.smith@lognpacific.org Query OfficeActivity | where TimeGenerated between (datetime(2026-08-05T18:59:27Z) .. datetime(2026-08-06T00:00:00Z)) | where UserId == "m.smith@lognpacific.org" | where Operation == "Set-Mailbox"

![Flag 10 evidence](assets/10.png)

#### Flag Data Block

> **FLAG**
> Set-Mailbox

**TIME (UTC):** 2026-08-05T19:45:07.000Z

**EVENT:** Mail is leaving the mailbox despite no inbox rule ever being created — because the forward wasn't set via a rule at all. Set-Mailbox is an Exchange admin cmdlet that can configure forwarding directly on the mailbox object itself (e.g. ForwardingSmtpAddress), a different mechanism with a different audit shape than the usual New-InboxRule/Set-InboxRule path. That's why an inbox-rule hunt comes back clean — this persistence lives one layer up, on the mailbox configuration, not the rule set.

**SOURCE:** LAW-Cyber-Range / OfficeActivity

**QUERY:**
```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-08-05T18:59:27Z) .. datetime(2026-08-06T00:00:00Z))
| where UserId == "m.smith@lognpacific.org"
| where Operation == "Set-Mailbox"
```

#### Findings

Set-Mailbox established mailbox-level forwarding without an inbox rule, so rule-only hunting would miss the persistence mechanism.

### Flag 11 — C7 - The Deleted Bounces

#### Flag Scenario

Flag 11: SoftDelete TIME (UTC): 2026-08-05T19:48:41.000Z EVENT: The forwarded mail bounced and generated NDR/notification messages in the mailbox - evidence that would normally flag the hidden forward. Those notifications were then removed via SoftDelete, an Exchange mailbox-item operation, cleaning up the trail right after the Set-Mailbox forward was configured. This is defense evasion layered directly on top of the persistence mechanism from C6. SOURCE: LAW-Cyber-Range / OfficeActivity QUERY: OfficeActivity | where TimeGenerated between (datetime(2026-08-05T19:45:07Z) .. datetime(2026-08-06T00:00:00Z)) | where UserId == "m.smith@lognpacific.org" | where Operation == "SoftDelete" Eleven down. Ready for the next one whenever you've got it. You Two risk detections on this identity were cleared while the session was still live. Before I assume an analyst did it, I check who or what actually cleared them. What did, and what reason did it record? Format: risk detail value View Hint Check the audit stream for any user or app actor first, before assuming a human. View Hint Read RiskDetail on the two dismissed rows. The admin-confirmed variant is a different value, so read it exactly. Tactic: platform action, not the attacker.

![Flag 11 evidence](assets/11.png)

#### Flag Data Block

> **FLAG**
> SoftDelete

**TIME (UTC):** 2026-08-05T19:48:41.000Z

**EVENT:** The forwarded mail bounced and generated NDR/notification messages in the mailbox — evidence that would normally flag the hidden forward. Those notifications were then removed via SoftDelete, an Exchange mailbox-item operation, cleaning up the trail right after the Set-Mailbox forward was configured. This is defense evasion layered directly on top of the persistence mechanism from C6.

**SOURCE:** LAW-Cyber-Range / OfficeActivity

**QUERY:**
```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-08-05T19:45:07Z) .. datetime(2026-08-06T00:00:00Z))
| where UserId == "m.smith@lognpacific.org"
| where Operation == "SoftDelete"
```

#### Findings

SoftDelete removed the NDR/notification artifacts generated by the hidden forward, adding defense evasion to the mailbox persistence.

### Flag 12 — C8 - The Auto-Dismissal

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

![Flag 12 evidence](assets/12.png)

#### Flag Data Block

> **FLAG**
> aiConfirmedSigninSafe

**TIME (UTC):** 2026-08-05T19:53:20.000Z

**EVENT:** Two risk detections on m.smith (RiskEventType: anonymizedIPAddress, RiskLevel: low) were cleared mid-session — not by an analyst, but by Entra ID Protection's own real-time risk engine, which dismissed them with RiskDetail aiConfirmedSigninSafe. The platform's automated confidence scoring effectively vouched for the attacker's session while it was still active, suppressing signal that might otherwise have prompted a human look.

**SOURCE:** LAW-Cyber-Range / AADUserRiskEvents

**QUERY:**
```kql
AADUserRiskEvents
| where TimeGenerated between (datetime(2026-08-05T00:00:00Z) .. datetime(2026-08-06T00:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| order by TimeGenerated asc
| project TimeGenerated, RiskEventType, RiskLevel, RiskState, RiskDetail, Source, DetectionTimingType
```

#### Findings

aiConfirmedSigninSafe cleared anonymized-IP risk during the active session, reducing the signal available for human escalation.

### Flag 13 — C9 - The Automated Burst

#### Flag Scenario

168 There is a one-minute burst of directory calls. I could key on the client app, but that is swappable, and I do not trust it. I want a measure out of the call pattern itself that a person could not produce. What measure, and why does it beat the app? Format: rate or ratio measure View Hint Count calls against unique targets over time. A tool walking objects leaves a rate a human cannot. View Hint Read the burst in MicrosoftGraphActivityLogs. The AppId is swappable, the ratio and the rate are not. Tactic: Discovery. 1 incorrect August 11, 2026 at 4:42 PM 1:1 incorrect August 11, 2026 at 4:42 PM 15.0313 incorrect August 11, 2026 at 3:30 PM 0.9112 incorrect August 11, 2026 at 3:29 PM 1.0987 incorrect August 11, 2026 at 3:28 PM 18.63 incorrect August 11, 2026 at 3:26 PM 2.95 incorrect August 11, 2026 at 3:23 PM 20.45 incorrect August 11, 2026 at 3:22 PM 1.3 incorrect August 11, 2026 at 3:19 PM 13.61 incorrect August 11, 2026 at 3:19 PM 5.833 incorrect August 11, 2026 at 3:16 PM 23 incorrect August 11, 2026 at 1:14 PM 23.41 incorrect August 11, 2026 at 1:14 PM 17.64 incorrect August 11, 2026 at 1:06 PM 1058.14 incorrect August 11, 2026 at 1:05 PM 1058.1 incorrect August 11, 2026 at 1:04 PM 13.62 incorrect August 11, 2026 at 1:04 PM 13.62 incorrect August 11, 2026 at 1:04 PM 17 incorrect August 11, 2026 at 1:03 PM 25 incorrect August 11, 2026 at 12:59 PM 14.774306604628679 incorrect August 11, 2026 at 12:59 PM 22.357846395552603 incorrect August 11, 2026 at 12:58 PM 14 incorrect August 11, 2026 at 12:58 PM 13 incorrect August 11, 2026 at 12:58 PM 22 incorrect August 11, 2026 at 12:58 PM 22.35 incorrect August 11, 2026 at 12:56 PM 22.35 incorrect August 11, 2026 at 12:56 PM 22 incorrect August 11, 2026 at 12:56 PM 701/28 incorrect August 11, 2026 at 12:55 PM 25.04 incorrect August 11, 2026 at 12:54 PM 28 incorrect August 11, 2026 at 12:53 PM 25.035714285714285 incorrect August 11, 2026 at 12:53 PM 25 incorrect August 11, 2026 at 12:53 PM 6 incorrect August 11, 2026 at 12:50 PM 5 incorrect August 11, 2026 at 12:49 PM 0

![Flag 13 evidence](assets/13.png)

#### Flag Data Block

> **FLAG**
> 20.08 calls per second

**TIME (UTC):** 2026-08-05T20:08:59.723Z – 2026-08-05T20:09:59.723Z (one-minute window)

**EVENT:** A sustained burst of 1205 Microsoft Graph API requests in exactly 60 seconds from IP 159.26.115.80, tool-fingerprinted as azurehound/v2.12.1 — a rate of 20.08 calls per second. The client app/AppId is not a trustworthy discriminator on its own, since it can be swapped or spoofed by attacker tooling. The call rate itself is not: no human clicking through a portal or manually issuing requests can sustain ~20 requests every second for a full minute. Within that same window the tool touched 891 distinct objects (roles, groups, service principals, applications), confirming this as systematic, automated directory enumeration rather than interactive browsing.

**SOURCE:** LAW-Cyber-Range / MicrosoftGraphActivityLogs

**QUERY:**
```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-08-05T20:08:59.723Z) .. datetime(2026-08-05T20:09:59.723Z))
| where IPAddress == "159.26.115.80"
| where UserAgent == "azurehound/v2.12.1"
| summarize TotalCalls = count(), UniqueTargets = dcount(tostring(split(RequestUri, "?")[0]))
| extend CallsPerSecond = todouble(TotalCalls) / 60
```

#### Findings

20.08 calls per second is the accepted behavioral measure. The rate is useful because the client identifier can be changed while sustained throughput remains an intrinsic property of the automated behavior.

### Flag 14 — C10 - The Refused Reads

#### Flag Scenario

150 Most of that burst came back fine. One class of read came back refused every time. What code, and what did being refused cost them? Format: response code and consequence View Hint Read the burst by response code, not just call count. Some reads came back refused. View Hint Group ResponseStatusCode and look at which URIs carry the refusals. Tactic: Privilege Escalation, attempted.

![Flag 14 evidence](assets/14.png)

#### Flag Data Block

> **FLAG**
> 403, blocked PIM role-eligibility/escalation enumeration

**TIME (UTC):** within the 20:08:59.723–20:10:19.391 burst

**EVENT:** Three calls in the AzureHound-driven burst returned 403 Forbidden rather than 200 — two of them against PIM endpoints (roleManagementPolicyAssignments, roleEligibilityScheduleInstances), one against a /users call requesting the signInActivity field. The compromised token's OAuth scopes didn't include the PIM-read permissions needed to enumerate role eligibility or activation policy, so the attacker's tooling was refused visibility into which accounts could self-escalate via PIM and under what conditions — a privilege-escalation reconnaissance path that came back blind.

**SOURCE:** LAW-Cyber-Range / MicrosoftGraphActivityLogs

**QUERY:**
```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-08-05T20:08:59Z) .. datetime(2026-08-05T20:10:20Z))
| where IPAddress == "159.26.115.80"
| where ResponseStatusCode != "200"
| project TimeGenerated, ResponseStatusCode, RequestUri, AppId
```

#### Findings

403 responses blocked PIM role-eligibility and escalation reconnaissance, leaving the compromised token blind to that privilege path.

### Flag 15 — C11 - The Single Record

#### Flag Scenario

172 Intel on this actor says they try to secure re-entry into the cloud. I want to know if they managed it here. There is exactly one directory-audit record for the identity. What is it, and what does it being the only one prove? Format: operation name and what it proves View Hint The technique they favour changes how the account authenticates. In AuditLogs, filter to the target identity and the Authentication Methods category. Pull every record and read the ActivityDisplayName for each - count them. Unlock Hint for 50 points There is one row and it is a read - the operation that reads current settings, not one that modifies them. Name that operation and state what the absence of any write proves about persistence. Tactic: Persistence, proven negative.

![Flag 15 evidence](assets/15.png)

#### Flag Data Block

> **FLAG**
> N/A

**TIME (UTC):** 2026-08-05T20:13:26.8298499Z

**EVENT:** The only directory-audit record initiated by m.smith is Settings_GetSettingsAsync, a read operation, executed from IP 135.232.161.225 during the same window as the browser-driven Graph cluster reading role management and directory objects. No write or registration event for a new authentication method exists anywhere in AuditLogs for this identity — despite intel indicating this actor's usual play is to plant a durable auth method for re-entry, the single record here shows only a settings check, proving that persistence attempt did not succeed in the cloud tenant.

**SOURCE:** LAW-Cyber-Range / AuditLogs

**QUERY:**
```kql
AuditLogs
| where TimeGenerated between (datetime(2026-08-05T00:00:00Z) .. datetime(2026-08-06T00:00:00Z))
| extend InitiatorUpn = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| extend InitiatorId = tostring(parse_json(InitiatedBy).user.id)
| where InitiatorUpn == "m.smith@lognpacific.org" or InitiatorId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| order by TimeGenerated asc
| project TimeGenerated, OperationName, ActivityDisplayName, Category, LoggedByService, AADOperationType, Result, InitiatorUpn, TargetResources
```

#### Findings

The identity’s only directory-audit record was Settings_GetSettingsAsync; the evidence supports that settings were read and the tested persistence mechanism was not established.

### Flag 16 — C12 - The Walled-Off Collector

#### Flag Scenario

169 The Graph side looks clean. The burst went out, it came back, and the easy read is that they mapped the tenant and moved on. But on the sign-in side the same client keeps coming back for forty minutes against something that has no calls behind it at all. What 55 / 113 - claudechattopdf.com is the client, what refused the second thing it was after, and what does the easy read miss? Format: client name, refusal code, resource refused View Hint The activity log only holds calls that were actually made. When there are none, look at where access is granted rather than where it is spent, for the same client against a different resource. Unlock Hint for 50 points In AADNonInteractiveUserSignInLogs, scope to the identity and that client, then compare ResourceDisplayName against ResultType. One resource never returns a success. The client names itself in UserAgent in the Graph log. Name the code and say what it walled off. Tactic: Privilege Escalation, attempted, proven negative across tables.

![Flag 16 evidence](assets/16.png)

#### Flag Data Block

> **FLAG**
> azurehound/v2.12.1, 50076, Azure Resource Manager

**TIME (UTC):** 2026-08-05T20:32:35.973Z – 2026-08-05T21:10:12.375Z

**EVENT:** While the Microsoft Graph enumeration burst (20:08:59–20:10:19) looks like a clean, complete tenant mapping pass, the same client — azurehound/v2.12.1 — separately spent roughly 38 minutes trying to obtain a token for Azure Resource Manager, the API surface for managing Azure subscriptions, resource groups, and infrastructure. Every attempt was refused with error 50076, requiring MFA the compromised session didn't have. Because none of these attempts ever produced a successful token, no corresponding calls exist in MicrosoftGraphActivityLogs — the activity log only records what actually got made, so this entire escalation attempt is invisible there. Reading Graph activity alone gives the false impression the actor mapped the tenant and stopped; the sign-in logs show they kept trying, for well over half an hour, to pivot from directory enumeration into direct control over Azure infrastructure, and were blocked at the identity layer the whole time.

**SOURCE:** LAW-Cyber-Range / AADNonInteractiveUserSignInLogs

**QUERY:**
```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(2026-08-05T00:00:00Z) .. datetime(2026-08-06T00:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where AppId == "1950a258-227b-4e31-a9cf-717495945fc2"
| where ResourceDisplayName == "Azure Resource Manager"
| order by TimeGenerated asc
| project TimeGenerated, ResourceDisplayName, ResultType, ResultDescription, ConditionalAccessStatus
```

#### Findings

AzureHound repeatedly sought Azure Resource Manager access and received 50076/MFA-required failures. Graph activity alone therefore understated the attempted escalation.

### Flag 17 — B1 - The Stolen Seed

#### Flag Scenario

166 Five hours on, the same identity walks onto the estate VPN first try, both factors satisfied, no failures at all. What second component did the service record, and how did they already hold it? Format: second factor component and source View Hint A one-time code lives thirty seconds. They were not relaying it - they held the seed. Ask where a seed lives, and what you already know they took. View Hint Read the two grantors on the LinuxAuth_CL OpenVPN record and give the second. Note LinuxAuth_CL uses Dvc/DvcHostname, not Computer. Tactic: MFA is not a control if the seed is stolen.

![Flag 17 evidence](assets/17.png)

#### Flag Data Block

> **FLAG**
> TOTP generated from a seed that was sitting in the restored Personal.kdbx

**TIME (UTC):** 2026-08-06T00:04:30.749Z

**EVENT:** Roughly five hours after the credential bridge file (VPN-Access-Credentials.txt) was accessed in the cloud phase, the identity authenticates cleanly to the estate VPN — both pam_unix (password) and pam_google_authenticator (TOTP) grantors satisfied on the first attempt, from IP 159.26.116.27, no failures logged. A live TOTP code only lives 30 seconds, ruling out interception or relay — the attacker instead already held the underlying seed, extracted from Personal.kdbx, the KeePass vault restored to a prior version during the cloud collection phase (C4). A stolen seed generates valid codes indefinitely, explaining the zero-friction MFA pass: the control wasn't bypassed, its secret was already in hand.

**SOURCE:** LAW-SilentCorridor / LinuxAuth_CL

**QUERY:**
```kql
LinuxAuth_CL
| where TimeGenerated between (datetime(2026-08-05T00:00:00Z) .. datetime(2026-08-06T12:00:00Z))
| where EventProduct == "OpenVPN"
| where EventType == "Logon"
| where TargetUsername has "m.smith"
| order by TimeGenerated asc
```

#### Findings

The successful VPN login satisfied both password and TOTP. The seed was already present in the restored Personal.kdbx, so a live code did not need to be intercepted.

### Flag 18 — B2 - The Internal Sweep

#### Flag Scenario

170 The internal reconnaissance is not in the on-prem SIEM at all. Before I 61 / 113 - claudechattopdf.com call that a gap I work out how the actor is witnessed internally, then find where the sweep actually landed. What destination port sequence shows the whole attack in one table? Format: port sequence comma between them View Hint The external address is absent on-prem - the gateway translates it to an internal address. Find what it collapses to, then pull NTANetAnalytics in the cloud workspace filtered on that internal address as the source. The question is which ports the sweep touched on the domain controller. Unlock Hint for 50 points Filter SrcIp to the translated internal address, DestIp to the domain controller. Sort DestPort ascending. The sweep is a full AD recon tool - it hits DNS, authentication, directory, and file sharing in a single pass. List every port you see to that host.

![Flag 18 evidence](assets/18.png)

#### Flag Data Block

> **FLAG**
> 53, 88, 135, 389, 445, 464, 636

**TIME (UTC):** 2026-08-06T01:04:08.6777868Z

**EVENT:** The internal reconnaissance sweep never appears in the on-prem SIEM directly — the VPN gateway NATs the attacker's external address, so the actor is only witnessed internally through translated traffic. Filtering NTANetAnalytics in the cloud workspace to AD-relevant destination ports isolates one source, 10.0.0.111, sweeping the domain controller (10.0.0.198) across DNS (53), Kerberos (88), RPC endpoint mapper (135), LDAP (389), SMB (445), kpasswd (464), and LDAPS (636) — a complete authentication/directory/file-sharing reconnaissance pass in a single session. Other internal hosts show similar port spreads but substitute Global Catalog ports (3268/3269) for kpasswd (464), marking them as routine domain-member traffic rather than the targeted sweep.

**SOURCE:** LAW-Cyber-Range / NTANetAnalytics

**QUERY:**
```kql
NTANetAnalytics
| where TimeGenerated between (datetime(2026-08-06T00:00:00Z) .. datetime(2026-08-06T02:00:00Z))
| where DestPort in (53, 88, 135, 389, 445, 464, 636, 3268, 3269)
| summarize DistinctPorts=dcount(DestPort), Ports=make_set(DestPort) by SrcIP, DestIP
| order by DistinctPorts desc
```

#### Findings

The translated source 10.0.0.111 swept the DC across 53, 88, 135, 389, 445, 464, and 636, covering DNS, authentication, directory, and file-sharing reconnaissance in one pass.

### Flag 19 — O1 - The Mapping Tool

#### Flag Scenario

Flag 19: SharpHound - inferred from the named-pipe/account-policy enumeration pattern; the tool itself was not directly observed TIME (UTC): 2026-08-06T12:01:45.904Z EVENT: A tight IPC$ named-pipe pattern on the DC (winreg, cert binds followed by randomly-named dropped artifacts) shows account/policy enumeration consistent with SharpHound. The tool identification is inferred from the behavioral fingerprint rather than directly observed; no process execution, command line, or binary telemetry names SharpHound. SOURCE: LAW-Cyber-Range / WindowsObjectAccess_CL QUERY: WindowsObjectAccess_CL | where TimeGenerated between (datetime(2026-08-06T11:55:00Z) .. datetime(2026-08-06T13:00:00Z)) | where SrcIpAddr == "10.1.0.120" | order by TimeGenerated asc | project TimeGenerated, RelativeTargetName, ShareName, ObjectName O2 - The Reset Actor Flag 20: svc_helpbot TIME (UTC): 2026-08-06T11:53:55.849895Z EVENT: A 4724 account-reset event shows the non-person identity svc_helpbot performing the reset against t.harris. The other reset in the same window was performed by GF-DC01$ against m.smith and is the benign one. SOURCE: LAW-Cyber-Range / WindowsAccountMgmt_CL EVENT/RECORD ID: 4724 QUERY: WindowsAccountMgmt_CL | where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07)) | where EventID == "4724" | order by TimeGenerated asc O3 - The Injected Block Flag 21: [GF-SEC-REMEDIATION] TIME (UTC): 2026-08-06T11:53:55.888899Z EVENT: A forged forwarded message was embedded inside a genuine printer-fault ticket. The injected block presented itself as an automated security notice and instructed the helpdesk assistant to reset t.harris. Its subject used the tag [GF-SEC-REMEDIATION]. SOURCE: LAW-Cyber-Range / LLMAgentLogs_CL QUERY: LLMAgentLogs_CL | where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07)) | where isnotempty(retrieved_content) | project TimeGenerated, retrieved_content | order by TimeGenerated asc O4 - The Gate Marker Flag 22: GF-IR-4488 TIME (UTC): 2026-08-06T11:53:55.888Z EVENT: The agent turn carried the reference marker GF-IR-4488, which the gate accepted as the authorization marker. SOURCE: LAW-Cyber-Range / LLMAgentLogs_CL QUERY: LLMAgentLogs_CL | where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07)) | where isnotempty(gate_marker_text) | project TimeGenerated, gate_marker_text | order by TimeGenerated asc O5 - The Tool Call Flag 23: reset_account_password TIME (UTC): 2026-08-06T11:53:55.85029Z EVENT: The MCP tool layer invoked reset_account_password for t.harris. The call succeeded and returned the target DN for Tom Harris. SOURCE: LAW-Cyber-Range / MCPToolCalls_CL QUERY: MCPToolCalls_CL  | where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T11:55:00Z)) | project TimeGenerated, mcp_server, tool, arguments, result, caller, session | order by TimeGenerated asc O6 - The Password Source Flag 24: password_source = caller_supplied TIME (UTC): 2026-08-06T11:53:55.85029Z EVENT: The MCP tool call recorded the new password source as caller_supplied, distinguishing this reset from benign self-service resets where the password is generated by the reset workflow itself. SOURCE: LAW-Cyber-Range / MCPToolCalls_CL QUERY: MCPToolCalls_CL | where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T11:55:00Z)) | project TimeGenerated, mcp_server, tool, arguments, result, caller, session | order by TimeGenerated asc O7 - The Cross-Account Reset Flag 25: tool_args.username = t.harris vs. ticket owner = m.smith TIME (UTC): 2026-08-06T11:53:55.85029Z EVENT: The agent turn requested a reset for t.harris, while the ticket owner/requester was m.smith. Neither the agent turn nor the reset event is suspicious in isolation - the signal only appears when the two are correlated: the account named in tool_args.username doesn't match who actually raised the ticket. SOURCE: LAW-Cyber-Range / LLMAgentLogs_CL + WindowsAccountMgmt_CL QUERY: LLMAgentLogs_CL | where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T11:55:00Z)) | project TimeGenerated, tool_args, retrieved_content, caller | order by TimeGenerated asc WindowsAccountMgmt_CL | where EventID == "4724" | where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T11:55:00Z)) | project TimeGenerated, SubjectUserName, TargetUserName | order by TimeGenerated asc That's the full picture on the AI-agent confused-deputy chain now - a forged security-notice block hidden in a legitimate ticket, walking the helpdesk agent through a marker it trusted without verifying, into a real AD password reset on the wrong account. Nicely closes the loop on "the system did exactly what it was told" from the hunt's own framing. Ready for whatever's next. You O8 - The Coverage Gap 173 I am not going to assume nothing fired. That would be comfortable and it would be wrong. I sweep the window in both workspaces for the reset, the group change and the agent tables, then read what actually did fire nearest to it. What does the sweep return, and what is the nearest High? Format: sweep result and nearest alert View Hint A negative needs proving. Sweep every rule query in the window across both workspaces before concluding. View Hint Sweep SecurityAlert in both workspaces for the reset actor, the ticket, and the agent table names. Then sort  what remains by severity and time. The nearest High is about something else entirely.

![Flag 19 evidence](assets/19.png)

#### Flag Data Block

> **FLAG**
> SharpHound — inferred from the named-pipe/account-policy enumeration pattern; the tool itself was not directly observed.

**TIME (UTC):** 2026-08-06T12:01:45.904Z

**EVENT:** A tight IPC$ named-pipe pattern on the DC shows account/policy enumeration consistent with SharpHound. The tool identification is inferred from the behavioral fingerprint rather than directly observed; no process execution, command line, or binary telemetry names SharpHound.

**SOURCE:** LAW-Cyber-Range / WindowsObjectAccess_CL

**QUERY:**
```kql
WindowsObjectAccess_CL
| where TimeGenerated between (datetime(2026-08-06T11:55:00Z) .. datetime(2026-08-06T13:00:00Z))
| where SrcIpAddr == "10.1.0.120"
| order by TimeGenerated asc
| project TimeGenerated, RelativeTargetName, ShareName, ObjectName
```

#### Findings

SharpHound is an inference from named-pipe behavior; no process execution, command line, or binary hash directly names the tool.

### Flag 20 — O2 - The Reset Actor

#### Flag Scenario

An account reset ran on the DC, and the thing that performed it is not a person. Two resets ran in this window and one of them is benign, so I compare who performed each and against whom. Which identity performed it? Format: account name View Hint Two resets in the window, one benign. Compare who performed each, and against whom. View Hint Read the 4724 in WindowsAccountMgmt_CL and give the actor. Note EventID is a string. Tactic: Persistence. O3 - The Injected Block 170 That reset came in as content the agent read, so I read the ticket. Under a genuine printer fault there is a block that did not come from the person who raised it. What tag does that block use to present itself as an automated security notice? Format: the tag, as it appears in the content View Hint Read the retrieved content, not just the tool call. What the agent obeyed is pasted into the ticket, dressed as authority. View Hint Read retrieved_content in LLMAgentLogs_CL. The forged block carries a subject line dressed as an automated security notice. Give the bracketed tag. O4 - The Gate Marker 170 The gate let this through because a marker was present, not because it was checked. It logged the marker it accepted. Which reference did the request carry? Format: the reference marker View Hint Approach: the gate recorded the marker it accepted. Read the gate fields on the agent turn, not the tool call. View Hint Pull gate_marker_text from LLMAgentLogs_CL on the in-window agent turn. Tactic: the confused-deputy failure. O5 - The Tool Call 125 Between the agent deciding and the write landing in AD, something executed the action. Three witnesses, one action, under forty milliseconds. What operation did the tool layer invoke? Format: operation name View Hint Three witnesses, one action. Order them by timestamp and read what the middle layer called it. View Hint Take the tool name from MCPToolCalls_CL. Tactic: Execution. O6 - The Password Source 170 The tool call records where the new password came from. One field in the arguments separates this reset from every benign one. Which field, and what value? Format: field = value View Hint A benign self-service reset generates its own password. Read what the tool call recorded about this one's source. View Hint The MCPToolCalls_CL arguments carry a source field nested in JSON, not as a column. Name the field and its value, and compare against a benign reset. Tactic: the cleanest discriminator in the scenario. O7 - The Cross-Account Reset 190 Neither half of this is suspicious on its own. That is what makes it hard. An agent turn, and a reset on the DC. Put them together and ask whether the account that was reset is the one the requester actually owns. Which pair of events, and which single field comparison is the signal? Format: the two sides of the comparison View Hint The agent reset an account. Before you accept it, check who raised the ticket. View Hint Correlate the agent turn in LLMAgentLogs_CL to the 4724 in WindowsAccountMgmt_CL. The field that matters is in tool_args, and the comparison is against who owns the ticket. Name both sides.

![Flag 20 evidence](assets/20.png)

#### Flag Data Block

> **FLAG**
> svc_helpbot

**TIME (UTC):** 2026-08-06T11:53:55.849895Z

**EVENT:** A 4724 account-reset event shows the non-person identity svc_helpbot performing the reset against t.harris. The other reset was performed by GF-DC01$ against m.smith and is the benign reset.

**SOURCE:** LAW-Cyber-Range / WindowsAccountMgmt_CL

EVENT/RECORD ID: 4724

**QUERY:**
```kql
WindowsAccountMgmt_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where EventID == "4724"
| order by TimeGenerated asc
```

#### Findings

svc_helpbot performed the malicious 4724 reset against t.harris; the parallel GF-DC01$ reset against m.smith was benign.

### Flag 21 — O3 - The Injected Block

#### Flag Scenario

That reset came in as content the agent read, so I read the ticket. Under a genuine printer fault there is a block that did not come from the person who raised it. What tag does that block use to present itself as an automated security notice? Format: the tag, as it appears in the content View Hint Read the retrieved content, not just the tool call. What the agent obeyed is pasted into the ticket, dressed as authority. View Hint Read retrieved_content in LLMAgentLogs_CL. The forged block carries a subject line dressed as an automated security notice. Give the bracketed tag. O4 - The Gate Marker 170 The gate let this through because a marker was present, not because it was checked. It logged the marker it accepted. Which reference did the request carry? Format: the reference marker View Hint Approach: the gate recorded the marker it accepted. Read the gate fields on the agent turn, not the tool call. View Hint Pull gate_marker_text from LLMAgentLogs_CL on the in-window agent turn. Tactic: the confused-deputy failure. O5 - The Tool Call 125 Between the agent deciding and the write landing in AD, something executed the action. Three witnesses, one action, under forty milliseconds. What operation did the tool layer invoke? Format: operation name View Hint Three witnesses, one action. Order them by timestamp and read what the middle layer called it. View Hint Take the tool name from MCPToolCalls_CL. Tactic: Execution. O6 - The Password Source 170 The tool call records where the new password came from. One field in the arguments separates this reset from every benign one. Which field, and what value? Format: field = value View Hint A benign self-service reset generates its own password. Read what the tool call recorded about this one's source. View Hint The MCPToolCalls_CL arguments carry a source field nested in JSON, not as a column. Name the field and its value, and compare against a benign reset. Tactic: the cleanest discriminator in the scenario. O7 - The Cross-Account Reset 190 Neither half of this is suspicious on its own. That is what makes it hard. An agent turn, and a reset on the DC. Put them together and ask whether the account that was reset is the one the requester actually owns. Which pair of events, and which single field comparison is the signal? Format: the two sides of the comparison View Hint The agent reset an account. Before you accept it, check who raised the ticket. View Hint Correlate the agent turn in LLMAgentLogs_CL to the 4724 in WindowsAccountMgmt_CL. The field that matters is in tool_args, and the comparison is against who owns the ticket. Name both sides.

![Flag 21 evidence](assets/21.png)

#### Flag Data Block

> **FLAG**
> [GF-SEC-REMEDIATION]

**TIME (UTC):** 2026-08-06T11:53:55.888899Z

**EVENT:** A forged forwarded message was embedded inside a genuine printer-fault ticket. The injected block presented itself as an automated security notice and instructed the helpdesk assistant to reset t.harris. Its subject used the tag [GF-SEC-REMEDIATION].

**SOURCE:** LAW-Cyber-Range / LLMAgentLogs_CL

**QUERY:**
```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where isnotempty(retrieved_content)
| project TimeGenerated, retrieved_content
| order by TimeGenerated asc
```

#### Findings

[GF-SEC-REMEDIATION] is the forged authority marker embedded in a genuine ticket, forming the content side of the confused-deputy attack.

### Flag 22 — O4 - The Gate Marker

#### Flag Scenario

The gate let this through because a marker was present, not because it was checked. It logged the marker it accepted. Which reference did the request carry? Format: the reference marker View Hint Approach: the gate recorded the marker it accepted. Read the gate fields on the agent turn, not the tool call. View Hint Pull gate_marker_text from LLMAgentLogs_CL on the in-window agent turn. Tactic: the confused-deputy failure. O5 - The Tool Call 125 Between the agent deciding and the write landing in AD, something executed the action. Three witnesses, one action, under forty milliseconds. What operation did the tool layer invoke? Format: operation name View Hint Three witnesses, one action. Order them by timestamp and read what the middle layer called it. View Hint Take the tool name from MCPToolCalls_CL. Tactic: Execution. O6 - The Password Source 170 The tool call records where the new password came from. One field in the arguments separates this reset from every benign one. Which field, and what value? Format: field = value View Hint A benign self-service reset generates its own password. Read what the tool call recorded about this one's source. View Hint The MCPToolCalls_CL arguments carry a source field nested in JSON, not as a column. Name the field and its value, and compare against a benign reset. Tactic: the cleanest discriminator in the scenario. O7 - The Cross-Account Reset 190 Neither half of this is suspicious on its own. That is what makes it hard. An agent turn, and a reset on the DC. Put them together and ask whether the account that was reset is the one the requester actually owns. Which pair of events, and which single field comparison is the signal? Format: the two sides of the comparison View Hint The agent reset an account. Before you accept it, check who raised the ticket. View Hint Correlate the agent turn in LLMAgentLogs_CL to the 4724 in WindowsAccountMgmt_CL. The field that matters is in tool_args, and the comparison is against who owns the ticket. Name both sides.

![Flag 22 evidence](assets/22.png)

#### Flag Data Block

> **FLAG**
> GF-IR-4488

**TIME (UTC):** 2026-08-06T11:53:55.888Z

**EVENT:** The agent turn carried the reference marker GF-IR-4488, which the gate accepted as the authorization marker.

**SOURCE:** LAW-Cyber-Range / LLMAgentLogs_CL

**QUERY:**
```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where isnotempty(gate_marker_text)
| project TimeGenerated, gate_marker_text
| order by TimeGenerated asc
```

#### Findings

GF-IR-4488 was accepted as the gate marker without validating its authority, enabling the action to pass.

### Flag 23 — O5 - The Tool Call

#### Flag Scenario

Between the agent deciding and the write landing in AD, something executed the action. Three witnesses, one action, under forty milliseconds. What operation did the tool layer invoke? Format: operation name View Hint Three witnesses, one action. Order them by timestamp and read what the middle layer called it. View Hint Take the tool name from MCPToolCalls_CL. Tactic: Execution. O6 - The Password Source 170 The tool call records where the new password came from. One field in the arguments separates this reset from every benign one. Which field, and what value? Format: field = value View Hint A benign self-service reset generates its own password. Read what the tool call recorded about this one's source. View Hint The MCPToolCalls_CL arguments carry a source field nested in JSON, not as a column. Name the field and its value, and compare against a benign reset. Tactic: the cleanest discriminator in the scenario. O7 - The Cross-Account Reset 190 Neither half of this is suspicious on its own. That is what makes it hard. An agent turn, and a reset on the DC. Put them together and ask whether the account that was reset is the one the requester actually owns. Which pair of events, and which single field comparison is the signal? Format: the two sides of the comparison View Hint The agent reset an account. Before you accept it, check who raised the ticket. View Hint Correlate the agent turn in LLMAgentLogs_CL to the 4724 in WindowsAccountMgmt_CL. The field that matters is in tool_args, and the comparison is against who owns the ticket. Name both sides.

![Flag 23 evidence](assets/23.png)

#### Flag Data Block

> **FLAG**
> reset_account_password

**TIME (UTC):** 2026-08-06T11:53:55.85029Z

**EVENT:** The MCP tool layer invoked reset_account_password for t.harris. The call succeeded and returned the target DN for Tom Harris.

**SOURCE:** LAW-Cyber-Range / MCPToolCalls_CL

**QUERY:**
```kql
MCPToolCalls_CL
| where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T11:55:00Z))
| project TimeGenerated, mcp_server, tool, arguments, result, caller, session
| order by TimeGenerated asc
```

#### Findings

reset_account_password is the MCP execution bridge between the agent decision and the AD password reset.

### Flag 24 — O6 - The Password Source

#### Flag Scenario

The tool call records where the new password came from. One field in the arguments separates this reset from every benign one. Which field, and what value? Format: field = value View Hint A benign self-service reset generates its own password. Read what the tool call recorded about this one's source. View Hint The MCPToolCalls_CL arguments carry a source field nested in JSON, not as a column. Name the field and its value, and compare against a benign reset. Tactic: the cleanest discriminator in the scenario. O7 - The Cross-Account Reset 190 Neither half of this is suspicious on its own. That is what makes it hard. An agent turn, and a reset on the DC. Put them together and ask whether the account that was reset is the one the requester actually owns. Which pair of events, and which single field comparison is the signal? Format: the two sides of the comparison View Hint The agent reset an account. Before you accept it, check who raised the ticket. View Hint Correlate the agent turn in LLMAgentLogs_CL to the 4724 in WindowsAccountMgmt_CL. The field that matters is in tool_args, and the comparison is against who owns the ticket. Name both sides.

![Flag 24 evidence](assets/24.png)

#### Flag Data Block

> **FLAG**
> password_source = caller_supplied

**TIME (UTC):** 2026-08-06T11:53:55.85029Z

**EVENT:** The MCP tool call recorded the new password source as caller_supplied, distinguishing this reset from benign self-service resets where the password is generated by the reset workflow.

**SOURCE:** LAW-Cyber-Range / MCPToolCalls_CL

**QUERY:**
```kql
MCPToolCalls_CL
| where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T11:55:00Z))
| project TimeGenerated, mcp_server, tool, arguments, result, caller, session
| order by TimeGenerated asc
```

#### Findings

password_source = caller_supplied separates the malicious reset from benign workflows that generate their own password.

### Flag 25 — O7 - The Cross-Account Reset

#### Flag Scenario

Neither half of this is suspicious on its own. That is what makes it hard. An agent turn, and a reset on the DC. Put them together and ask whether the account that was reset is the one the requester actually owns. Which pair of events, and which single field comparison is the signal? Format: the two sides of the comparison View Hint The agent reset an account. Before you accept it, check who raised the ticket. View Hint Correlate the agent turn in LLMAgentLogs_CL to the 4724 in WindowsAccountMgmt_CL. The field that matters is in tool_args, and the comparison is against who owns the ticket. Name both sides.

![Flag 25 evidence](assets/25.png)

#### Flag Data Block

> **FLAG**
> tool_args.username = t.harris vs. ticket owner = m.smith

**TIME (UTC):** 2026-08-06T11:53:55.85029Z

**EVENT:** The agent turn requested a reset for t.harris, while the ticket owner/requester was m.smith. The mismatch between the account in tool_args.username and the ticket owner is the cross-account signal.

**SOURCE:** LAW-Cyber-Range / LLMAgentLogs_CL + WindowsAccountMgmt_CL

**QUERY:**
```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T11:55:00Z))
| project TimeGenerated, tool_args, retrieved_content, caller
| order by TimeGenerated asc
WindowsAccountMgmt_CL
| where EventID == "4724"
| where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T11:55:00Z))
| project TimeGenerated, SubjectUserName, TargetUserName
| order by TimeGenerated asc
```

#### Findings

The reset target t.harris did not match the ticket owner m.smith. The signal appears only when the agent and AD reset records are correlated.

### Flag 26 — O8 - The Coverage Gap

#### Flag Scenario

173 I am not going to assume nothing fired. That would be comfortable and it would be wrong. I sweep the window in both workspaces for the reset, the group change and the agent tables, then read what actually did fire nearest to it. What does the sweep return, and what is the nearest High? Format: sweep result and nearest alert View Hint A negative needs proving. Sweep every rule query in the window across both workspaces before concluding. View Hint Sweep SecurityAlert in both workspaces for the reset actor, the ticket, and the agent table names. Then sort 76 / 113 - claudechattopdf.com what remains by severity and time. The nearest High is about something else entirely.

![Flag 26 evidence](assets/26.png)

#### Flag Data Block

> **FLAG**
> None, GF Pipe - Post-Exploitation Framework Named Pipe

**TIME (UTC):** 2026-08-06T11:53:19.4616443Z (nearest High) vs. reset at 11:53:55.849895Z

**EVENT:** A full sweep of SecurityAlert in both LAW-Cyber-Range and LAW-SilentCorridor across the reset window returns nothing tied to svc_helpbot, t.harris, the forged ticket, the gate marker, or the MCPToolCalls_CL invocation — the entire confused-deputy chain generated zero detections. The nearest High-severity alert by time is a genuine GF Pipe - Post-Exploitation Framework Named Pipe alert (distinct from the T3 false-positive instance the day before), 36 seconds ahead of the reset — real post-exploitation signal, but topically unrelated to the reset/agent chain itself. The absence had to be proven by sweeping, not assumed from silence.

**SOURCE:** LAW-Cyber-Range + LAW-SilentCorridor / SecurityAlert

**QUERY:**
```kql
SecurityAlert
| where TimeGenerated between (datetime(2026-08-06T11:00:00Z) .. datetime(2026-08-06T12:30:00Z))
| order by TimeGenerated asc
| project TimeGenerated, AlertName, AlertSeverity, Description, CompromisedEntity
(run against both workspaces)
```

#### Findings

The sweep found no alert tied to the reset/agent chain. The Flags document records the nearest High as GF Pipe at 11:53:19.4616443Z; the gap is a detection-coverage finding.

### Flag 27 — O9 - The Certificate

#### Flag Scenario

150 The reset account then requests something and receives it sixty milliseconds later. One table records both halves. What did it obtain? Format: certificate template name Unlock Hint for 0 points The gap is a single request-and-issue pair, and one table records both halves. Unlock Hint for 50 points Read the 4886/4887 pair in WindowsCertServices_CL, matching on 80 / 113 - claudechattopdf.com RequestId. Note it has no EventID column, it uses EventOriginalType. Tactic: Credential Access.

![Flag 27 evidence](assets/27.png)

#### Flag Data Block

> **FLAG**
> GF-PrivilegedAccessLogon

**TIME (UTC):** 2026-08-06T12:02:54.423Z (request) → issuance ~60ms later

**EVENT:** t.harris — the account reset earlier in the chain via the confused-deputy agent action — requests a certificate off the GF-PrivilegedAccessLogon template via RPC/NTLM, and receives it roughly sixty milliseconds later. The request (4886) and issuance (4887) are two halves of the same operation, correlated by RequestId, both recorded in WindowsCertServices_CL. Obtaining a certificate this quickly after a reset extends the compromise from a simple password change into a durable, certificate-based credential — one that can be used for authentication independent of the account's password going forward.

**SOURCE:** LAW-SilentCorridor / WindowsCertServices_CL

**QUERY:**
```kql
WindowsCertServices_CL
| where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T12:30:00Z))
| where EventOriginalType in ("4886", "4887")
| order by RequestId asc, TimeGenerated asc
| project TimeGenerated, EventOriginalType, RequestId, Requester, CertificateTemplate, Subject, SubjectAlternativeName
```

#### Findings

GF-PrivilegedAccessLogon was issued about 60 ms after the request, creating durable certificate-based authentication independent of the original password.

### Flag 28 — O10 - The Binding Question

#### Flag Scenario

194 This DC enforces strong certificate binding, so a certificate it cannot prove belongs to the holder gets refused. This one was accepted. So either the binding failed, or there was nothing for it to catch. I need to understand which before I can say where the privilege actually came from. Format: the SAN and the privilege source - two parts. Give the identity the certificate carried, and name the specific mechanism in the template that granted the privilege. General answers (EKU, template name, group membership) are not specific enough. [Updated 8 Aug] Grader clarified - both halves are scored. Read the certificate issuance record and the template configuration. The privilege source is a specific architectural feature of the template, not a general certificate property. View Hint Ask what identity the certificate actually carried. Was any part of it false, or was it the enrollee's own? View Hint Read SubjectAlternativeName on the 4887 and compare it to the enrollee. If nothing in it is false the binding control had nothing to reject, so the privilege came from elsewhere in the template. Say where. Tactic: Privilege Escalation

![Flag 28 evidence](assets/28.png)

#### Flag Data Block

> **FLAG**
> t.harris@greenfield.local (genuine, unspoofed UPN); privilege granted via Authentication Mechanism Assurance — the template's issuance policy OID maps to a privileged security group at logon

**TIME (UTC):** 2026-08-06T12:02:54.4833852Z

**EVENT:** The issued certificate's SubjectAlternativeName carries Principal Name=t.harris@greenfield.local — his own genuine UPN, exactly matching the requester. Nothing was spoofed, so strong certificate binding had nothing to reject. The privilege escalation isn't identity fraud; it comes from the template's architecture itself — GF-PrivilegedAccessLogon carries an Issuance Policy OID that Active Directory maps directly to a privileged security group at logon time (Authentication Mechanism Assurance). Simply holding a certificate issued off this template confers the group-equivalent privilege, independent of t.harris's actual static AD group membership.

**SOURCE:** LAW-SilentCorridor / WindowsCertServices_CL

**QUERY:**
```kql
WindowsCertServices_CL
| where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T12:30:00Z))
| where EventOriginalType == "4887"
| where EventData has "t.harris"
| project TimeGenerated, DvcHostname, EventOriginalType, CertificateTemplate, EventData
```

#### Findings

The certificate carried the genuine t.harris@greenfield.local identity, so strong binding had nothing to reject. The privilege source was the template’s Authentication Mechanism Assurance architecture.

### Flag 29 — O11 - The Silent Group Add

#### Flag Scenario

125 Nobody added this account to a privileged group, yet minutes later it holds rights a standard user does not. Then it goes and collects one thing so a new membership actually takes effect. Which group? Format: group name Unlock Hint for 0 points Read the group-membership change events in the window. One adds an account to a privileged group without 85 / 113 - claudechattopdf.com any admin action. Unlock Hint for 50 points Find the 4728 in SecurityEvent. The group name is in the event. Tactic: Privilege Escalation.

![Flag 29 evidence](assets/29.png)

#### Flag Data Block

> **FLAG**
> GF-Tier0-Automation

**TIME (UTC):** 2026-08-06T12:06:45.6302382Z

**EVENT:** t.harris adds his own account to GF-Tier0-Automation, a security-enabled global group — the SubjectUserName on the 4728 is t.harris himself, not an administrator. No human authorized this change; it was possible only because the certificate issued minutes earlier (O10, GF-PrivilegedAccessLogon) conferred privilege via Authentication Mechanism Assurance, giving the account rights a standard user account would never hold. Group membership doesn't take effect in an account's access token until a fresh Kerberos ticket is issued, so the account still needs to re-authenticate before this new membership is actually usable.

**SOURCE:** LAW-SilentCorridor / SecurityEvent

**QUERY:**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-08-06T00:00:00Z) .. datetime(2026-08-07T00:00:00Z))
| where EventID == 4728
| order by TimeGenerated asc
| project TimeGenerated, SubjectUserName, TargetUserName, MemberName
```

#### Findings

t.harris added himself to GF-Tier0-Automation using privilege established by the certificate path, not a normal admin authorization workflow.

### Flag 30 — O12 - The Five-Second Extraction

#### Flag Scenario

194 Every account's secrets left the DC in under five seconds, I can see the right that was exercised in the security log, and I can see that nothing touched host memory. Those two facts together should tell me the method. I want to prove the technique from the right, not guess it from the absence. What technique, and why is there no memory trace? Format: technique and the replication right Unlock Hint for 0 points The right is recorded in SecurityEvent 4662. Look at the GUID and the count. The technique is named for the right, not the tool. Unlock Hint for 50 points In SecurityEvent 4662, extract the replication right by GUID and count it across the burst. The count of the secret-bearing right is itself the scale of what left. Tactic: Credential Access.

![Flag 30 evidence](assets/30.png)

#### Flag Data Block

> **FLAG**
> DCSync — DS-Replication-Get-Changes-All (paired with DS-Replication-Get-Changes)

**TIME (UTC):** 2026-08-06T12:10:17.4133796Z

**EVENT:** t.harris, now holding rights via GF-Tier0-Automation membership, exercises DS-Replication-Get-Changes-All 39 times against GF-DC01 within a five-second window — the specific extended right required to replicate secret attributes (password hashes), not just ordinary object data. DS-Replication-Get-Changes fires alongside it (78 hits) as the paired, lower-privilege half of the same replication handshake. This is DCSync: the DC hands over the data because the requester legitimately holds the replication permission, over the DRSUAPI protocol — the same mechanism one real DC uses to sync with another. No credential-dumping tool ever touches lsass.exe or host memory, because the technique doesn't read secrets out of a running process at all; it asks the DC to replicate them, and the DC complies. That absence of memory access isn't a detection gap, it's the proof the technique is right-based, not memory-based.

**SOURCE:** LAW-SilentCorridor / SecurityEvent

**QUERY:**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-08-06T12:00:00Z) .. datetime(2026-08-06T13:00:00Z))
| where EventID == 4662
| where SubjectUserName has "harris"
| summarize Count=count() by Properties, AccessMask
| order by Count desc
```

#### Findings

The 4662 data shows DS-Replication-Get-Changes-All (39 hits) paired with DS-Replication-Get-Changes (78 hits): DCSync through replication rights, without LSASS/memory access.

### Flag 31 — O13 - The Surviving ACE

#### Flag Scenario

194 One change here outlives the account. That is the one that matters. There are two writes to the same object and one of them changed nothing at all, so I cannot baseline off the latest write. And a dangerous-permissions audit reports this object clean. Which entry, and why does the audit miss it? Format: the real write timestamp and the no-op judgement Unlock Hint for 0 points The persistence is a permission, not a membership. Read the domain root's security descriptor, and do not baseline by the latest write. One of the two changed nothing. Unlock Hint for 50 points Pair the WindowsDirChanges_CL writes by correlation id and compare the descriptor content on each side, not the object's latest state. One pair genuinely alters it, the other is identical on both sides. Say which write is real and what the other one is. The added entry is a control-access right, which a full-control-only filter never returns. Tactic: Persistence.

![Flag 31 evidence](assets/31.png)

#### Flag Data Block

> **FLAG**
> real write = 2026-08-06T12:10:22.873Z/.874Z (adds CR ACE for t.harris's SID, no ObjectType GUID — blanket control-access grant); the 12:50:14.895Z write is a no-op, descriptor unchanged

**TIME (UTC):** 2026-08-06T12:10:22.874Z

**EVENT:** Two writes touch the domain root's nTSecurityDescriptor. The first (12:10:22.873/.874Z, seconds before the DCSync burst) adds ACE (A;OICI;CR;;;S-1-5-21-...-1107) — a blanket Control Access Right for t.harris, unscoped to any specific extended-right GUID, meaning it covers DS-Replication-Get-Changes-All among everything else. The second (12:50:14.895Z) rewrites the same descriptor with no net change — a no-op that would mislead any baseline built off the most recent timestamp. A full-control-only dangerous-permissions audit never flags the real ACE, because CR grants are a different permission category from GenericAll/WriteDACL/WriteOwner — the object reports clean while carrying standing, membership-independent persistence.

**SOURCE:** LAW-SilentCorridor / WindowsDirChanges_CL

**QUERY:**
```kql
WindowsDirChanges_CL
| where TimeGenerated between (datetime(2026-08-06T00:00:00Z) .. datetime(2026-08-06T13:00:00Z))
| where AttributeLDAPDisplayName == "nTSecurityDescriptor"
| order by TimeGenerated asc
| project TimeGenerated, SubjectAccount, TargetObject, EventData
```

#### Findings

The real persistence write is the 12:10:22.873/.874Z Control Access Right ACE addition for t.harris; the 12:50:14.895Z write was a no-op. Full-control-only ACL checks miss this permission category.

### Flag 32 — O14 - The Benign Twin

#### Flag Scenario

174 The same replication operation ran forty-five minutes before the attacker held the target, and nothing alerted on it. Before I call that a miss I ask why the rule ignored it. Was it hostile, and which principal ran it? Format: principal account Unlock Hint for 0 points Two principals, same operation, one alert. Ask why the rule ignored the earlier one before assuming it missed it. Unlock Hint for 50 points Look at what kind of account performed the earlier one, and at the clock. The rule carries an exclusion by design. Tactic: discriminator.

![Flag 32 evidence](assets/32.png)

#### Flag Data Block

> **FLAG**
> GF-DC01$

**TIME (UTC):** 2026-08-06T11:31:25.843863Z

**EVENT:** The same DS-Replication-Get-Changes / DS-Replication-Get-Changes-All operation ran 45 minutes before t.harris's DCSync, performed by GF-DC01$ — the domain controller's own computer account. This is routine, expected inter-DC replication traffic, not an attack. The detection rule carries a by-design exclusion for DC computer-account principals, since AD replication between domain controllers is constant and legitimate; the rule only fires when a user principal (not ending in $) exercises the replication right, which is precisely what distinguished t.harris's 12:10 DCSync as hostile.

**SOURCE:** LAW-SilentCorridor / SecurityEvent

**QUERY:**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-08-06T10:30:00Z) .. datetime(2026-08-06T12:15:00Z))
| where EventID == 4662
| where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" or Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by SubjectUserName
| order by FirstSeen asc
```

#### Findings

GF-DC01$ performed the earlier replication operation and was ignored by design because legitimate DC replication uses the same rights.

### Flag 33 — O15 - The Scheduling Gap

#### Flag Scenario

150 The rule was right. It caught the replication and it correctly excluded the machine account, so the logic is not the problem. I compare when the replication happened against when the incident opened. What is the gap? Format: duration and whether it is scheduling or logic View Hint The rule was right. Compare the time of the replication against the time the incident opened. Unlock Hint for 50 points Read the interval from SecurityIncident.CreatedTime, not the alert's StartTime, which is the detection-window start. Say whether it is scheduling or logic. Tactic: detection latency.

![Flag 33 evidence](assets/33.png)

#### Flag Data Block

> **FLAG**
> 36m46s, scheduling

**TIME (UTC):** First activity 2026-08-06T12:16:37Z -> Incident created 2026-08-06T12:53:23.166667Z

**EVENT:** The rule "GF Directory - Replication Rights By Non-Machine Account" correctly detected the hostile replication and correctly excluded the DC's own machine account (O14) — the logic was never in question. The 36-minute-46-second gap between the alert's first witnessed activity and the incident's creation reflects the rule's scheduled evaluation cadence, not a detection flaw: a scheduled analytic rule only runs at fixed intervals, so the incident doesn't open until the rule's next scheduled pass after the hostile activity occurred.

**SOURCE:** LAW-SilentCorridor / SecurityAlert + SecurityIncident

**QUERY:**
```kql
SecurityIncident
| where TimeGenerated between (datetime(2026-08-06T12:00:00Z) .. datetime(2026-08-06T13:00:00Z))
| where Severity == "High"
| order by CreatedTime asc
Cross-referenced against the alert "GF Directory - Replication Rights By Non-Machine Account" (LAW-SilentCorridor), First activity 12:16:37 PM, Generated 12:53:22 PM.
```

#### Findings

The corrected source block records 36m46s of scheduling latency from first activity 12:16:37Z to incident creation 12:53:23.166667Z. The detection logic itself was not the problem.

### Flag 34 — O16 - The Published Key

#### Flag Scenario

150 The last file read is a policy file off a domain share, world-readable for years, and the object-access log names it directly. Its value is whatever is stored inside it and how weakly that is protected. What credential does it yield? Format: the credential The file was recovered from the estate and is attached below. The object-access log names the path it was read from. Extract the credential from the file contents. Unlock Hint for 0 points Unlock Hint for 50 points WindowsObjectAccess_CL names the path directly. The stored secret decrypts offline with a key published years ago. Recover it. Tactic: Credential Access.

![Flag 34 evidence](assets/34.png)

#### Flag Data Block

> **FLAG**
> GPPstillStandingStrong2k18

**TIME (UTC):** 2026-08-06T12:59:07.757Z

**EVENT:** The last file read off a domain share is Groups.xml, pulled from SYSVOL at greenfield.local\Policies{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml by 10.1.0.120 — a Group Policy Preferences file defining a local admin account (helpdesk) with a cpassword field. GPP cpassword values are AES-256-CBC "encrypted," but Microsoft published the fixed 32-byte key on MSDN in 2012 after the mechanism was found to provide no real security, since SYSVOL is readable by any authenticated domain user by design. Decrypting offline with the long-published key yields the plaintext credential: GPPstillStandingStrong2k18.

**SOURCE:** Recovered file (Groups.xml) + LAW-SilentCorridor / WindowsObjectAccess_CL

**QUERY:**
```kql
WindowsObjectAccess_CL
| where TimeGenerated between (datetime(2026-08-06T00:00:00Z) .. datetime(2026-08-07T00:00:00Z))
| where ObjectName has "Groups.xml" or RelativeTargetName has "Groups.xml"
| project TimeGenerated, SrcIpAddr, RelativeTargetName, ShareName, ObjectName
```

#### Findings

Groups.xml contained a GPP cpassword recoverable with the published key, yielding GPPstillStandingStrong2k18 and exposing a reusable credential.

### Flag 35 — O17 - The Recovery Account

#### Flag Scenario

125 One of the files taken holds three credentials, and they are not equal. On a domain controller one of them matters far more than the other two. Which one? Format: credential or account name The file was recovered from the estate during evidence collection and is attached below. Three credentials, three blast radii. Unlock Hint for 0 points Three credentials, three blast radii. Which one compromises the DC's own recovery path? Credentials.txt: Greenfield Logistics - recovered from GF-DC01 File: C:\IT\credentials.txt Last modified: 2026-03-15 DC DSRM: DSRM_Gr33nfield! FileZilla FTP (gf-web01): ftp_backup / Ft9$xLm2024 svc_backup service account: Greenfield2024

![Flag 35 evidence](assets/35.png)

#### Flag Data Block

> **FLAG**
> DSRM_Gr33nfield!

**TIME (UTC):** 2026-08-06T12:58:47.505Z

**EVENT:** Of the three credentials recovered in credentials.txt (read from \*\IT\credentials.txt by 10.1.0.120), only one grants power over the domain controller's own operating system independent of Active Directory itself — the DSRM (Directory Services Restore Mode) password. Set once at DC promotion and rarely rotated, it functions as local administrator on the DC's underlying OS and is often overlooked in credential-rotation policy entirely, unlike domain accounts subject to normal password-change enforcement. The FileZilla FTP credential is scoped to a single web server; the svc_backup account is a domain principal bound by AD's normal permission model. The DSRM password bypasses that model altogether.

**SOURCE:** Recovered file (credentials.txt) + LAW-SilentCorridor / WindowsObjectAccess_CL

**QUERY:**
```kql
WindowsObjectAccess_CL
| where TimeGenerated between (datetime(2026-08-06T00:00:00Z) .. datetime(2026-08-07T00:00:00Z))
| where ObjectName has "credentials.txt" or RelativeTargetName has "credentials.txt"
| project TimeGenerated, SrcIpAddr, RelativeTargetName, ShareName, ObjectName
```

#### Findings

DSRM_Gr33nfield! is the highest-impact credential in credentials.txt because it controls the DC’s own recovery mode independently of normal AD account controls.

### Flag 36 — O18 - The Fallback

#### Flag Scenario

174 Two identities did the collection. One touched the shares and stopped, the other swept them. There is no denial event anywhere in the log. That absence is itself a finding, but only if I can reconstruct the handover from what IS present. Which identity actually read the files, and what do the logs not capture? Format: the identity that read the files and how many distinct shares they accessed Unlock Hint for 0 points Compare which shares each identity touched and when. One binds the enumeration pipes and stops, the other sweeps. The denial event is not there, so reason from its absence. Unlock Hint for 50 points In SecurityEvent 5140/5145, group by account and share across the collection window and count each. One account holds a single administrative share, the other spans many. Check which account the failure events belong to before you read the absence. Tactic: fallback by absence and sequence, not a captured denial.

![Flag 36 evidence](assets/36.png)

#### Flag Data Block

> **FLAG**
> m.smith, 9 distinct shares

**TIME (UTC):** 2026-08-06T12:58:47.505Z

**EVENT:** m.smith is the identity associated with the file-reading activity from 10.1.0.120. The collection spans 9 distinct shares. The logs do not capture a denial event documenting the handover; that transition is reconstructed from the identities, timestamps, and share-access sequence.

**SOURCE:** LAW-SilentCorridor / SecurityEvent + WindowsObjectAccess_CL

**QUERY:**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-08-06T12:00:00Z) .. datetime(2026-08-06T13:15:00Z))
| where EventID == 4624
| where IpAddress == "10.1.0.120"
| order by TimeGenerated asc
| project TimeGenerated, TargetUserName, LogonType, IpAddress
```

#### Findings

m.smith is the identity associated with the 10.1.0.120 file-reading activity across 9 distinct shares. The logs do not record an explicit denial/handover event; the transition is reconstructed from sequence and scope.

### Flag 37 — O19 — The Disclosure Threshold

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

![Flag 37 evidence](assets/37.png)

#### Flag Data Block

> **FLAG**
> employee_records.csv

**TIME (UTC):** 2026-08-06T12:59:01.229Z

**EVENT:** employee_records.csv was taken from the \\*\Finance share. Unlike credentials.txt, it is not a credential store. Its contents identify an individual who is not otherwise part of the incident, making the file the collection artifact that crosses the disclosure/breach threshold and starts the notification obligation.

**SOURCE:** LAW-SilentCorridor / WindowsObjectAccess_CL + recovered employee_records.csv

**QUERY:**
```kql
WindowsObjectAccess_CL
| where TimeGenerated between (datetime(2026-08-06T00:00:00Z) .. datetime(2026-08-07T00:00:00Z))
| where ObjectName has "employee_records.csv" or RelativeTargetName has "employee_records.csv"
| project TimeGenerated, SrcIpAddr, RelativeTargetName, ShareName, ObjectName
| order by TimeGenerated asc
```

#### Findings

employee_records.csv is the collection artifact that crosses the disclosure/breach threshold because it identifies an otherwise uninvolved individual, changing the incident’s notification implications.

### Flag 38 — S1 - The Coverage Inversion

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

![Flag 38 evidence](assets/38.png)

#### Flag Data Block

> **FLAG**
> LLMAgentLogs_CL

**TIME (UTC):** 2026-08-06T11:53:55.888899Z

**EVENT:** LLMAgentLogs_CL is the custom table holding the richest evidence for the agent-driven attack chain, including the retrieved ticket content, tool invocation, gate decision, authorization marker, and tool arguments/results. Despite that high evidentiary value, the workspace has zero analytic rules watching this table. It therefore sits at the top of the evidence ranking while sitting at the bottom of detection coverage—the coverage inversion identified by S1.

**SOURCE:** LAW-SilentCorridor / LLMAgentLogs_CL

**QUERY:**
```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-08-06T00:00:00Z) .. datetime(2026-08-07T00:00:00Z))
| project TimeGenerated, session_id, actor, tool_name, tool_args, tool_result, gate_decision, gate_reason, gate_marker_text
| order by TimeGenerated asc
```

#### Findings

LLMAgentLogs_CL contains the richest agent-chain evidence but has zero analytic-rule coverage, creating a clear coverage inversion.

### Flag 39 — S2 - The Cross-Source Rule

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

![Flag 39 evidence](assets/39.png)

#### Flag Data Block

> **FLAG**
> LLMAgentLogs_CL + WindowsAccountMgmt_CL: gate_reason == "authorisation_marker_present" AND target account != ticket requester

**TIME (UTC):** 2026-08-06T11:53:55.888899Z

**EVENT:** The compromise evidence is recorded in LLMAgentLogs_CL, while the resulting password reset is recorded in WindowsAccountMgmt_CL. A cross-source rule should correlate the agent turn with the 4724 reset and trigger when the gate records authorisation_marker_present while the account being reset differs from the ticket requester.

**SOURCE:** LAW-SilentCorridor / LLMAgentLogs_CL + WindowsAccountMgmt_CL

**QUERY:**
```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-08-06T11:53:00Z) .. datetime(2026-08-06T11:54:30Z))
| where gate_reason == "authorisation_marker_present"
| extend TargetAccount = tostring(parse_json(tool_args).username)
| join kind=inner (
    WindowsAccountMgmt_CL
    | where EventID == "4724"
    | project ResetTime=TimeGenerated, TargetUsername, ActorUsername
) on $left.TargetAccount == $right.TargetUsername
| where TargetAccount != actor
| project TimeGenerated, actor, TargetAccount, gate_reason, ResetTime, ActorUsername
```

#### Findings

A cross-source rule should correlate authorisation_marker_present, the agent target, and the 4724 reset so a target/requester mismatch becomes a deterministic alert.

### Flag 40 — S3 - The Response Failure

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> Detection without response; incident-response process / alert triage and escalation

**TIME (UTC):** 2026-08-06T12:53:22Z

**EVENT:** The classic techniques were detected and correlated, so the failure was not in detection or tooling. The incident that fired was not converted into an effective response. The cheapest control is a process control: mandatory alert triage and escalation with an incident-response playbook, ensuring a detected high-confidence incident is acted on rather than simply recorded.

**SOURCE:** LAW-SilentCorridor / SecurityAlert + SecurityIncident

**QUERY:**
`N/A`

#### Findings

The evidence shows detection without effective response: the failure is the incident-response process and escalation path, not the availability of telemetry.

### Flag 41 — IR1 - Session Containment

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> Revoke/invalidate the active session first; a password reset alone does not terminate an already-issued live session/token

**TIME (UTC):** N/A

**EVENT:** The attacker holds a replayed session rather than the password, so the first containment action is to invalidate/revoke the active session or token. A password reset alone does not kill an already-issued live session. After session invalidation, credentials can be reset and fresh authentication required.

**SOURCE:** Incident response guidance / scenario

**QUERY:**
`N/A`

#### Findings

Invalidate the active session/token first. Password reset alone does not necessarily terminate an already-issued replayed session.

### Flag 42 — IR2 - The IP Blocking Question

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> Reject, unless the four IPs are confirmed stable, attacker-controlled, unique, and not shared with legitimate traffic

**TIME (UTC):** N/A

**EVENT:** Blanket IP blocking should be rejected until the four exit addresses are verified as stable, uniquely associated with the attacker, and not shared by legitimate traffic. Blocking unverified or shared addresses could disrupt legitimate users while providing limited containment if the attacker can rotate exit addresses.

**SOURCE:** Incident response guidance / scenario

**QUERY:**
`N/A`

#### Findings

Reject blanket IP blocking until the four exits are proven stable, unique, attacker-controlled, and not shared with legitimate traffic.

### Flag 43 — IR3 - The krbtgt Rotation

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> Rotate krbtgt twice, with the rotations separated by a sufficient interval for previously issued Kerberos tickets to expire.

**TIME (UTC):** N/A

**EVENT:** Rotate krbtgt twice, with the rotations separated by a sufficient interval for previously issued Kerberos tickets to expire.

**SOURCE:** Incident response guidance / scenario

**QUERY:**
`N/A`

#### Findings

Rotate krbtgt twice with sufficient separation for previously issued Kerberos tickets to expire.

### Flag 44 — IR4 - Is It Contained

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> No. The attacker is not evicted because the persistence survives all three actions. The certificate-based persistence does not depend on the account being enabled, the Tier 0 group membership, or the original certificate remaining valid.

**TIME (UTC):** N/A

**EVENT:** No. The attacker is not evicted because the persistence survives all three actions. The certificate-based persistence does not depend on the account being enabled, the Tier 0 group membership, or the original certificate remaining valid.

**SOURCE:** Incident response guidance / scenario

**QUERY:**
`N/A`

#### Findings

No: the three actions do not evict the attacker because certificate-based persistence survives account, group, and original-certificate changes.

### Flag 45 — IR5 - The Template Problem

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> No. Revoking the certificate only invalidates that specific certificate. To close the ADCS persistence path, fix or disable the vulnerable certificate template and remove the privilege path that allows the attacker to obtain another certificate.

**TIME (UTC):** N/A

**EVENT:** No. Revoking the certificate only invalidates that specific certificate. To close the ADCS persistence path, fix or disable the vulnerable certificate template and remove the privilege path that allows the attacker to obtain another certificate.

**SOURCE:** Incident response guidance / scenario

**QUERY:**
`N/A`

#### Findings

No: revoking the current certificate is insufficient. The vulnerable AD CS template and privilege path must also be removed or disabled.

### Flag 46 — IR6 - Detection vs Authorisation

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> Reject. A detection rule only fires after the action has occurred, so it cannot prevent this class of authorisation failure. The alternative is preventive authorisation controls at the gate, requiring independent verification of the requester and target account before allowing the action.

**TIME (UTC):** N/A

**EVENT:** Reject. A detection rule only fires after the action has occurred, so it cannot prevent this class of authorisation failure. The alternative is preventive authorisation controls at the gate, requiring independent verification of the requester and target account before allowing the action.

**SOURCE:** Incident response guidance / scenario

**QUERY:**
`N/A`

#### Findings

Reject detection-only prevention. Authorization controls at the gate must independently verify the requester and target before allowing the reset.

### Flag 47 — IR7 - The Forwarding Hunt

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> The inbox-rule hunt fails because the forwarding was set with Set-Mailbox, which changes the mailbox forwarding property rather than creating an inbox rule. Instead, remove the unauthorized mailbox-level forwarding configuration.

**TIME (UTC):** N/A

**EVENT:** The inbox-rule hunt fails because the forwarding was set with Set-Mailbox, which changes the mailbox forwarding property rather than creating an inbox rule. Instead, remove the unauthorized mailbox-level forwarding configuration.

**SOURCE:** OfficeActivity / Incident response guidance

**QUERY:**
`N/A`

#### Findings

An inbox-rule hunt fails because the persistence is mailbox-level Set-Mailbox forwarding. Remove the unauthorized mailbox-level forwarding configuration.

### Flag 48 — IR8 - The MFA Failure

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> TOTP re-enrolment is insufficient because the attacker has possession of the existing TOTP seed and can continue generating valid codes. The alternative is to revoke the compromised TOTP factor and move the account to phishing-resistant MFA, such as FIDO2/WebAuthn.

**TIME (UTC):** N/A

**EVENT:** TOTP re-enrolment is insufficient because the attacker has possession of the existing TOTP seed and can continue generating valid codes. The alternative is to revoke the compromised TOTP factor and move the account to phishing-resistant MFA, such as FIDO2/WebAuthn.

**SOURCE:** Incident response guidance / scenario

**QUERY:**
`N/A`

#### Findings

TOTP re-enrollment is insufficient while the old seed is compromised. Revoke the factor and move to phishing-resistant MFA such as FIDO2/WebAuthn.

### Flag 49 — IR9 - Rank the Interventions

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> Incident response and escalation: The highest-impact intervention. A high-confidence alert had already fired; opening and escalating the incident would have allowed containment before the attacker could continue the chain.
> Preventive authorisation controls: Require independent verification that the requester is authorised to reset the target account. This would have stopped the confused-deputy action before execution.
> Cross-source detection and correlation: Correlate LLMAgentLogs_CL with WindowsAccountMgmt_CL so the injected agent request and resulting reset are detected together. This improves detection, but it is less impactful than acting on an alert that already fired or preventing the action.

**TIME (UTC):** N/A

**EVENT:** Same as the flag above.

**SOURCE:** Incident response guidance / scenario

**QUERY:**
`N/A`

#### Findings

The highest-impact intervention is acting on the already-fired high-confidence incident, followed by preventive authorization control, then cross-source correlation.

### Flag 50 — IR10 - The Rotation List

#### Flag Scenario

**Source availability:** The supplied exported Claude transcript does not contain the original challenge-question text for this flag. I have therefore not fabricated a supposedly exact prompt; the authoritative Flag Data Block from `Flags(2).docx` is preserved below.

#### Flag Data Block

> **FLAG**
> 1. krbtgt (double rotation), 2. DSRM/DC Admin, 3. GPP/SYSVOL (strip source first to prevent re-burning), 4. Service accounts, 5. User accounts, 6. App credentials.

**TIME (UTC):** N/A

**EVENT:** Rotations ordered from widest blast radius down to isolated services. GPP/SYSVOL sources must be stripped before credential resets to prevent immediate re-exposure.

**SOURCE:** Incident response guidance / scenario

**QUERY:**
`N/A`

#### Findings

Rotate by blast radius: krbtgt, DSRM/DC Admin, remove GPP/SYSVOL sources, then service accounts, user accounts, and application credentials.

## Overall Findings

The evidence supports a continuous compromise chain rather than isolated detections. The earliest identity action predates the headline stolen-session alert; the cloud session then pivots through a malicious email/file path, restores a credential vault, retrieves VPN access material, establishes mailbox forwarding and cleanup, performs automated Graph reconnaissance, and attempts an Azure Resource Manager escalation that is blocked at the token layer.

The same compromise crosses into the on-prem estate through VPN authentication using a TOTP seed recovered from the restored KeePass vault. On-prem, the actor performs targeted AD reconnaissance, abuses an AI-assisted helpdesk workflow to reset a different account, obtains a privileged certificate, self-adds to a Tier-0 group, performs DCSync using directory-replication rights, and leaves a Control Access Right ACE on the domain root that survives ordinary membership-based remediation.

The defensive picture is mixed. Important signals existed, but automation and process gaps reduced their value: automated risk confidence dismissed suspicious sign-ins, agent telemetry had no analytic-rule coverage, the hidden mailbox forward was not represented as a normal inbox-rule event, and a high-confidence incident was not converted into effective response. The response therefore has to combine session invalidation with durable credential rotation, AD CS/template remediation, GPP/SYSVOL cleanup, and preventive authorization controls.

## Source / Evidence Notes

- The hunt brief defines the hybrid platform, two-workspace telemetry model, Advanced Hunting/Sentinel KQL surface, and contaminated/shared-query constraint. fileciteturn1file9L510-L539
- `Flags(2).docx` specifies the Markdown image-placement convention as `assets/x.png` and supplies the authoritative Flag Data Blocks. fileciteturn1file6L311-L328
- The transcript confirms the accepted C9 answer as **20.08 calls per second** and ties it to 1,205 Graph requests in the strict one-minute window. fileciteturn4file0L40-L60
- The transcript and Flags document identify the 13 no-query flags as T1, T2, S3, and IR1–IR10. fileciteturn1file0L22-L39

**Source-integrity limitation:** the exported Claude transcript does not expose original challenge-question text for S1/S2 or IR1–IR10. Those sections therefore explicitly identify the missing source text rather than inventing wording. All 50 Flag Data Blocks are still included.
