# Pivot Point

*Cross-domain threat investigation for Microsoft 365*

Connecting the evidence between workloads—without reinventing the incident queue.

A read-only, locally generated Azure Workbook companion to Microsoft's **Hybrid Attack – Cloud & Identity** solution. This package adds focused investigation context; it does not replace Defender XDR incident correlation, Sentinel health monitoring, or Purview detections.

**Status:** local package. No tenant connection, cloud deployment, enabled detection, automatic response, or historical tenant replay has been performed. Local tests validate structure and behavioral specifications, not live KQL execution or Azure acceptance.

## Included

- Scenario-level source and linkage-key readiness for this extension's nine tables, including pre-window history observations and ingestion-lag measurements.
- A standalone OAuth consent → previously unseen application activity hunt, with a nonoverlapping 14-day historical baseline, ordered 24-hour sequence, configurable event threshold, and application-ID correlation. No IP-only app attribution.
- Exact-entity lookup of existing alerts and related incident links. This is analyst-directed association, not automatic deduplication of every hunt candidate.
- Optional email delivery/click context linked by message ID **and recipient**.
- Optional M365 audit and Purview Information Protection context, preserving observed operations, outcomes, object IDs, and label IDs without claiming exfiltration.
- Workbook JSON, an ARM template deploying **only one shared workbook**, a source/hash manifest, standard-library build tooling, and local tests.

The optional email and data panels default to **Off**. Each source union has a typed empty fallback so missing tables can be skipped without fabricating evidence. Missing table resolution can still produce warnings; schema, authorization, service-wide, or execution failures are not guaranteed to be suppressed. Inspect query warnings and readiness before interpreting an empty panel.

## Files

| Path | Purpose |
|---|---|
| `queries\*.kql` | Editable query sources; workbook parameter tokens are intentional |
| `queries\scenario-readiness.kql` | Generated from the source contract in `tools\build.py` |
| `workbook\cross-domain-extension.workbook.json` | Generated workbook for inspection or Advanced Editor import |
| `deployment\workbook.template.json` | Generated, deterministic ARM deployment template |
| `deployment\manifest.json` | Upstream reference, source contracts, query hashes, validation state |
| `tools\build.py` | Reproducible generator; Python standard library only |
| `tests\test_package.py` | Structural checks and synthetic behavioral specifications |

No packages need to be installed.

## Build and local validation

From this directory in PowerShell:

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -B .\tools\build.py
python -B -m unittest discover -s .\tests -v
```

The builder writes only the generated query, workbook, template, and manifest. Other query sources remain editable. Rebuild after changing query sources, source contracts, or workbook layout. Treat the generator as the source of truth for generated files.

The local tests cover serialized ARM/workbook round-tripping, matching source hashes, parameter declarations/encoding, optional panel defaults, query time envelopes, missing-source fallbacks, app-ID joins, strict baseline boundaries, thresholds, event ordering, and synthetic positive/negative cases. **The behavioral model is a specification, not a KQL interpreter.**

## Prerequisites for tenant validation

- Microsoft Sentinel workspace and appropriate read/query permissions for each desired table. Existing solution installation is recommended for complementary Azure/endpoint/hybrid-AD views; this extension has no runtime dependency on upstream workbook files.
- Access to `AuditLogs` and `CloudAppEvents` for the OAuth hunt. `AADServicePrincipalSignInLogs` is needed when an explicit client AppId is not recorded in the consent target's modified properties.
- `SecurityAlert` and `SecurityIncident` for alert/incident association. Appropriate Defender integration and incident synchronization must already be configured.
- Optional: `EmailEvents` and `UrlClickEvents` for email context; `OfficeActivity` and/or `MicrosoftPurviewInformationProtection` for data-impact context.
- Applicable workload licenses, connectors, audit configuration, retention and permissions. Installing the workbook does not supply these.
- At least 14 days of relevant pre-window CloudAppEvents history before interpreting application novelty. A history count alone does not establish completeness.

Query permissions and source RBAC remain enforced. The workbook does not grant access. Email subjects, URLs, file locations, identities and labels may be sensitive; share only with authorized analysts.

## Deployment — manual and not performed by this build

Use the target subscription and resource group approved by your organization. The principal needs workbook write permission in the target resource group; viewers separately need access to the selected workspace and data. This template assigns no roles and changes no connectors, rules, policies, or audit settings.

Example commands, **only after approval**, using an already available Azure CLI:

```powershell
$resourceGroup = '<approved-resource-group>'
$workspaceId = '/subscriptions/<subscription-id>/resourceGroups/<workspace-rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>'
az deployment group validate --resource-group $resourceGroup --template-file .\deployment\workbook.template.json --parameters workspaceResourceId=$workspaceId
az deployment group what-if --resource-group $resourceGroup --template-file .\deployment\workbook.template.json --parameters workspaceResourceId=$workspaceId
# Inspect the plan before choosing to execute this command:
az deployment group create --resource-group $resourceGroup --template-file .\deployment\workbook.template.json --parameters workspaceResourceId=$workspaceId
```

Resource IDs and URLs use Azure's slash-delimited syntax; local file paths use Windows backslashes. Choose `location=<approved-region>` if the resource group's region is not appropriate. No deployment parameter or credential file is needed. The deterministic workbook ID is specific to the target resource group and source workspace; redeploying to the same pair updates this workbook. Export any analyst edits before redeploying.

For manual workbook import, copy the generated workbook JSON into an Azure Workbook Advanced Editor. Replace `__WORKSPACE_RESOURCE_ID__` with the full approved workspace resource ID in both the parameter default and fallback resource list, or use the ARM template, which performs this replacement. Save as a new workbook rather than overwriting Microsoft's workbook. Do not paste ARM template JSON into the workbook editor.

Rollback is deletion of **this workbook resource only**, identified by the deployment output `workbookResourceId`. Do not delete the resource group, upstream solution, rules, or workspace.

## Investigation workflow

1. Select the workspace and a nonempty investigation period entirely within the **last 30 days**. The default is 24 hours. A visible scope-status panel explains unsupported periods; other panels deliberately return no rows for those periods.
2. Read source readiness and query warnings. No current events is not proof a connector is broken; missing/inaccessible tables are not proof an attack was absent.
3. Review OAuth hunt results. An optional AppId filter is an Entra application **client ID**, not its service-principal object ID. Minimum activity defaults to five recorded events; it is not a confidence score.
4. Supply an exact Entity for related alerts. Supported comparisons include account UPN/object ID/SID, IP, host name/FQDN, cloud app AppId and Azure resource ID when those fields exist in the alert's entity payload. No bare-account-name or substring matching is used.
5. Open the original incident URL where present. An unmatched alert or missing incident is not evidence that Microsoft missed an attack.
6. Enable optional email context using the exact recipient UPN or a NetworkMessageId. A supplied message ID takes precedence and returns its recipients. Identity object IDs are not automatically converted to UPNs.
7. Enable optional data context using an exact UPN. Review operations and outcomes individually. A failed operation, label, access event, or sharing invitation is not confirmed data theft.

Each panel supplies independent evidence. The package does **not** automatically prove a six-workload chain, assign threat-actor attribution, or determine causality.

### Query time envelope

Workbook requests use a 90-day service envelope, rather than the selected current period, to avoid clipping the 14-day baseline and 30-day pre-period incident snapshot lookup. Individual source queries apply narrower explicit filters. Supported investigation periods are within the last 30 days; this envelope is not a promise that 90 days of data exists. In a standalone query editor, replace parameter tokens and choose a service time range that also includes the baseline and incident lookback.

### OAuth mapping and evidence limits

Only the named consent/grant audit operations are included. An app must be resolvable through an explicit AppId-like modified property or an unambiguous service-principal sign-in map. Unresolved events are **excluded**, not assigned an identity using IP. CloudAppEvents.OAuthAppId must correspond to the Entra client AppId. The readiness view probes linkage fields but cannot certify every audit variant or mapping path. Validate representative delegated consent, admin consent and app-role grant payloads in your tenant.

Activity event counts are recorded-row counts, not distinct mailboxes, files, bytes, sessions, or confirmed API requests. Multiple consent records may produce overlapping candidates for the same app. No production alert grouping/suppression policy is implemented.

### Other explicit limits

- Incident snapshots are restricted to 30 days before the selected period through its end. Older snapshots, non-ingested alerts, unsupported entity formats, scoped access and sync delay can prevent association.
- Email context does not include attachment sandboxing, every URL payload, forwarded-message attribution, endpoint execution, token replay, or successful authentication inference.
- Purview support is Information Protection and selected M365 audit operations, **not** all DLP, Insider Risk, catalog classification, eDiscovery or sensitive-information types. No object-ID joins assume that a later label was present at access time.
- MDI, MDE, Azure control/data-plane evidence chains and repairs to the other 53 upstream hunts remain outside this extension. Use the original solution/native incidents; no duplicate cloud/endpoint detection pack is included.
- No guarantee of marketplace-wide novelty, detection precision, performance, live schema compatibility, cloud availability or production readiness is made by local validation.

## Required acceptance checks before operational use

1. Validate/what-if the ARM template, then import into an approved nonproduction context.
2. Execute each panel against real source schemas. Check warnings, parameter substitution, permissions, optional panel toggles, incident links and empty/missing-table behavior.
3. Replay known app activity before the baseline boundary, exactly at the boundary, during the current period, before/after consent and outside the 24-hour sequence. Confirm unrelated apps cannot join by IP.
4. Verify client-ID resolution for each actual consent audit variant and ensure legitimate/new applications are reviewed as benign counterexamples.
5. Compare findings against Defender XDR incidents, native detections and installed Content Hub content. Do not convert redundant findings into new alerts.
6. Measure query cost, latency, output volume and retention adequacy using your environment; adjust supported scenarios before broad use.
7. Only then consider separately approved production rule engineering. This package contains no enabled or disabled rule-deployment resources.

## Provenance and references

This is original companion content, not a Microsoft-supported fork or a redistribution of the 54-query solution. The upstream baseline defect motivated a separate, narrower OAuth hunt; the new query deliberately uses different linkage and has documented coverage tradeoffs.

- [Upstream solution, inspected commit 9a9e5cf](https://github.com/Azure/Azure-Sentinel/tree/9a9e5cf33a477ebc349b5c2c013d990246b45303/Solutions/Hybrid%20Attack%20-%20Cloud%20%26%20Identity)
- [Upstream OAuth hunt](https://github.com/Azure/Azure-Sentinel/blob/9a9e5cf33a477ebc349b5c2c013d990246b45303/Solutions/Hybrid%20Attack%20-%20Cloud%20%26%20Identity/Hunting%20Queries/Discovery/oauth-consent-followed-by-firstseen-oauthappid-burst.yaml)
- [Workbook parameter formatting](https://learn.microsoft.com/en-us/azure/azure-monitor/visualize/workbooks-parameters)
- [CloudAppEvents table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/cloudappevents)
- [EmailEvents table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/emailevents)
- [UrlClickEvents table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/urlclickevents)
- [Purview Information Protection table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftpurviewinformationprotection)
- [Sentinel connector health](https://learn.microsoft.com/en-us/azure/sentinel/monitor-data-connector-health)

Threat-reporting context: [Storm-2949, May 18, 2026](https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/), [passkey-themed social engineering, September 9, 2026](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/), and [Storm-3168, September 25, 2026](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/). These inform investigation priorities, not claims that this package detects those actors or covers every reported technique. Refresh the reporting and overlap review before adding rules.
