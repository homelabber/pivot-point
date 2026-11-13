"""Build a read-only Azure Workbook package using only the Python standard library."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCES = [
    ('AuditLogs', 'OAuth consent', "isnotempty(tostring(TargetResources))", 'Consent target and operation must be available'),
    ('AADServicePrincipalSignInLogs', 'OAuth app-ID mapping', 'isnotempty(ServicePrincipalId) and isnotempty(AppId)', 'Needed when consent audit lacks explicit application ID'),
    ('CloudAppEvents', 'OAuth activity', 'isnotempty(tostring(OAuthAppId))', 'Requires application IDs compatible with Entra AppId'),
    ('SecurityAlert', 'Related alerts', 'isnotempty(SystemAlertId) and isnotempty(tostring(Entities))', 'Entity fields must support exact matching'),
    ('SecurityIncident', 'Related incidents', 'isnotempty(tostring(AlertIds))', 'Alert-ID linkage required; historical snapshots may be outside query window'),
    ('EmailEvents', 'Optional email', 'isnotempty(NetworkMessageId) and isnotempty(RecipientEmailAddress)', 'Recipient and message ID required'),
    ('UrlClickEvents', 'Optional email clicks', 'isnotempty(NetworkMessageId) and isnotempty(AccountUpn)', 'Clicks without message IDs cannot be linked'),
    ('OfficeActivity', 'Optional data-impact audit', 'isnotempty(UserId) and isnotempty(OfficeObjectId)', 'Operation and outcome require analyst interpretation'),
    ('MicrosoftPurviewInformationProtection', 'Optional Purview labels', 'isnotempty(UserId) and isnotempty(ObjectId)', 'Does not include all Purview/DLP/Insider Risk signals'),
]


def read_zone(path):
    try:
        raw = Path(str(path) + ':Zone.Identifier').read_bytes()
    except FileNotFoundError:
        return None
    if len(raw) > 65536:
        raise ValueError(f'Zone stream too large: {path}')
    text = raw.decode('utf-16') if raw.startswith(b'\xff\xfe') else raw.decode('utf-8-sig')
    active = False
    for line in text.split('\0')[0].splitlines():
        line = line.strip(' \t\r')
        if line.startswith(';'):
            continue
        if line.startswith('['):
            if active:
                return None
            active = bool(re.match(r'^\[[ \t]*ZoneTransfer[ \t]*\]', line))
        elif active and re.match(r'^ZoneId[ \t]*=', line):
            value = line.split('=', 1)[1].strip(' \t')
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            value = value.lstrip(''.join(map(chr, range(33))))
            match = re.match(r'([+-]?)(?:(0[xob])([0-9a-fA-F]+)|([0-9]+))', value)
            if not match:
                return None
            sign, prefix, digits, decimal = match.groups()
            radix = {'0x': 16, '0o': 8, '0b': 2}.get(prefix, 10)
            valid = ''
            for char in digits or decimal:
                if char.lower() not in '0123456789abcdef'[:radix]:
                    break
                valid += char
            if not valid:
                return None
            zone = (int(valid, radix) * (-1 if sign == '-' else 1)) & 0xffffffff
            return zone if zone <= 4 else None
    return None


def mark(path):
    if read_zone(path) not in (3, 4):
        Path(str(path) + ':Zone.Identifier').write_text('[ZoneTransfer]\nZoneId=3\nHostUrl=about:internet\n', encoding='utf-8')
    if read_zone(path) not in (3, 4):
        raise ValueError(f'Could not verify file metadata: {path}')


def write(path, text):
    # Reading first ensures a stricter existing stream is never lost through replacement.
    zone = read_zone(path)
    path.write_text(text, encoding='utf-8', newline='\n')
    if zone == 4 and read_zone(path) != 4:
        raise ValueError(f'Stricter metadata changed: {path}')
    mark(path)


def readiness():
    legs = []
    for table, scenario, keys, note in SOURCES:
        legs.append(f"""({table}
    | where TimeGenerated >= StartTime - 14d and TimeGenerated <= EndTime
    | summarize CurrentEvents=countif(TimeGenerated >= StartTime),
        UsableKeyEvents=countif(TimeGenerated >= StartTime and ({keys})),
        HistoricalEvents=countif(TimeGenerated < StartTime),
        FirstObserved=min(TimeGenerated), LastObserved=max(TimeGenerated),
        MaximumLagMinutes=max(datetime_diff('minute', ingestion_time(), TimeGenerated))
    | extend Source='{table}', Scenario='{scenario}', ProbeResolved=1, Notes='{note}')""")
    seeds = ',\n'.join(f"    '{t}', '{s}', '{n}'" for t, s, _, n in SOURCES)
    return """let StartTime = {TimeRange:start};
let EndTime = {TimeRange:end};
let Expected = datatable(Source:string, Scenario:string, Notes:string) [
""" + seeds + """
];
let Observed = union isfuzzy=true
    (datatable(Source:string, Scenario:string, Notes:string, ProbeResolved:long, CurrentEvents:long, UsableKeyEvents:long, HistoricalEvents:long, FirstObserved:datetime, LastObserved:datetime, MaximumLagMinutes:long) []),
""" + ',\n'.join(legs) + """;
Expected
| join kind=leftouter (Observed | project-away Scenario, Notes) on Source
| extend State=case(isnull(ProbeResolved), 'Unavailable or inaccessible: inspect query warnings',
    CurrentEvents == 0, 'No events in selected period: not proof of connector failure',
    UsableKeyEvents == 0, 'Events present but required linkage keys absent',
    'Observed usable keys: validate operation-level coverage'),
    Baseline=iff(coalesce(HistoricalEvents, 0) == 0, 'No pre-window history observed', 'History observed; completeness not established')
| project Source, Scenario, State, CurrentEvents, UsableKeyEvents, HistoricalEvents, Baseline,
    FirstObserved, LastObserved, MaximumLagMinutes, Notes
| where StartTime >= ago(30d) and EndTime <= now() + 5m and StartTime < EndTime
| order by Source asc
"""


def markdown(name, text):
    return {'type': 1, 'name': name, 'content': {'json': text}}


def panel(name, title, query):
    return {'type': 3, 'name': name, 'content': {
        'version': 'KqlItem/1.0', 'title': title, 'query': query,
        'size': 0, 'queryType': 0, 'resourceType': 'microsoft.operationalinsights/workspaces',
        'crossComponentResources': ['{Workspace}'],
        'timeContext': {'durationMs': 7776000000},
        'visualization': 'table',
        'noDataMessage': 'No matching rows in this scope. Check scope status, source readiness, warnings and permissions; this is not a safety or detection verdict.'}}


def text_parameter(name, label, value=''):
    return {'id': name, 'name': name, 'type': 1, 'isRequired': False, 'value': value,
            'label': label, 'typeSettings': {'password': False}}


def build():
    generated = ROOT / 'queries' / 'scenario-readiness.kql'
    write(generated, readiness())
    queries = {p.stem: p.read_text(encoding='utf-8') for p in sorted((ROOT / 'queries').glob('*.kql'))}
    parameters = [
        {'id': 'Workspace', 'name': 'Workspace', 'type': 5, 'isRequired': True,
         'value': '__WORKSPACE_RESOURCE_ID__', 'label': 'Sentinel workspace',
         'typeSettings': {'resourceTypeFilter': {'microsoft.operationalinsights/workspaces': True},
                          'additionalResourceOptions': [], 'showDefault': False}},
        {'id': 'TimeRange', 'name': 'TimeRange', 'type': 4, 'isRequired': True,
         'value': {'durationMs': 86400000}, 'label': 'Investigation period',
         'typeSettings': {'selectableValues': [3600000, 14400000, 86400000, 604800000]}},
        text_parameter('Entity', 'Exact UPN, object ID, SID, host, IP or resource ID'),
        text_parameter('AppId', 'Optional Entra application (client) ID'),
        text_parameter('MessageId', 'Optional NetworkMessageId (takes precedence over recipient)'),
        {'id': 'MinimumEvents', 'name': 'MinimumEvents', 'type': 2, 'isRequired': True,
         'value': '5', 'label': 'Minimum OAuth activity events',
         'jsonData': '[{"value":"1","label":"1"},{"value":"5","label":"5"},{"value":"10","label":"10"},{"value":"25","label":"25"}]'},
        {'id': 'ShowEmail', 'name': 'ShowEmail', 'type': 2, 'isRequired': True, 'value': '0',
         'label': 'Show optional email evidence', 'jsonData': '[{"value":"0","label":"Off"},{"value":"1","label":"On"}]'},
        {'id': 'ShowData', 'name': 'ShowData', 'type': 2, 'isRequired': True, 'value': '0',
         'label': 'Show optional data-impact evidence', 'jsonData': '[{"value":"0","label":"Off"},{"value":"1","label":"On"}]'},
    ]
    intro = """# Pivot Point
*Cross-domain threat investigation for Microsoft 365*

Read-only companion to Microsoft's **Hybrid Attack – Cloud & Identity**, not a replacement incident queue or detection engine.

**No results does not mean safe or undetected.** Check source readiness, field mappings, query warnings, retention and RBAC first. Optional sources may be unavailable without breaking other panels. This package has not been executed against your tenant.

Choose a workspace and a period entirely within the **last 30 days**. Older/future periods are unsupported and evidence panels return no rows. A fixed 90-day query envelope prevents the service time picker from clipping baseline/snapshot queries; each query still filters its own narrower event windows. Use **Entity** for an exact UPN (email/data), or a supported native alert entity (incident lookup). Use **AppId** for the OAuth hunt. Results from different panels are independent evidence, not an automatically proven attack chain. Optional email and data panels are off by default.
"""
    items = [markdown('overview', intro), {'type': 9, 'name': 'parameters',
             'content': {'version': 'KqlParameterItem/1.0', 'parameters': parameters, 'style': 'pills'}},
             panel('scope', 'Investigation scope and validation status', queries['investigation-scope']),
             markdown('readiness-note', '## Scenario readiness\nTable-level probes cover this extension only—not all 54 upstream hunts. They do not replace Sentinel connector health monitoring. Missing/inaccessible tables may be skipped with warnings; a 14-day history count does not certify a complete baseline.'),
             panel('readiness', 'Source readiness and linkage keys', queries['scenario-readiness']),
             markdown('oauth-note', '## OAuth consent → new application activity\nA strict pre-window 14-day baseline avoids the upstream overlapping-baseline defect. Correlation requires an explicit Entra client AppId or an unambiguous service-principal-to-AppId mapping; IP-only correlation is not used. Unresolvable consent records are intentionally excluded. Validate that CloudAppEvents.OAuthAppId uses the same identifier. Event volume is not a maliciousness score.'),
             panel('oauth', 'Ordered OAuth hunt candidates (not enabled detections)', queries['oauth-consent-followed-by-new-app-activity']),
             markdown('incident-note', '## Existing alert / incident association\nRequires a nonempty Entity and exact supported entity fields. This is not automatic candidate deduplication. SecurityIncident uses the latest snapshot within the queried 30-day pre-period window; older or unsynchronized incidents may not appear. No match means no match found in this query scope—not that Microsoft missed an attack.'),
             panel('incidents', 'Related native alerts and incident links', queries['related-incidents'])]
    for kind, parameter, title, note in [
        ('email-evidence', 'ShowEmail', 'Optional message and click evidence', 'Message and recipient keys are required. Recipient must be an exact UPN unless MessageId is supplied. No inferred token theft, malware execution or attribution.'),
        ('data-impact', 'ShowData', 'Optional data-impact audit context', 'Exact UPN required. Object IDs and labels are displayed as recorded, not joined to infer content or classification at another time. This is not comprehensive DLP/Insider Risk coverage or confirmed exfiltration.')]:
        items.append({'type': 12, 'name': kind + '-group', 'conditionalVisibility': {
            'parameterName': parameter, 'comparison': 'isEqualTo', 'value': '1'},
            'content': {'version': 'NotebookGroup/1.0', 'groupType': 'editable',
                        'items': [markdown(kind + '-note', '## ' + title + '\n' + note),
                                  panel(kind, title, queries[kind])]}})
    workbook = {'version': 'Notebook/1.0', 'items': items,
                'fallbackResourceIds': ['__WORKSPACE_RESOURCE_ID__'],
                '$schema': 'https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json'}
    serialized = json.dumps(workbook, ensure_ascii=False, separators=(',', ':'))
    write(ROOT / 'workbook' / 'cross-domain-extension.workbook.json', json.dumps(workbook, indent=2, ensure_ascii=False) + '\n')
    arm = {
        '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
        'contentVersion': '1.0.0.0',
        'parameters': {
            'workspaceResourceId': {'type': 'string', 'minLength': 1, 'metadata': {'description': 'Full Sentinel Log Analytics workspace resource ID.'}},
            'location': {'type': 'string', 'defaultValue': '[resourceGroup().location]'},
            'workbookName': {'type': 'string', 'defaultValue': "[guid(resourceGroup().id, parameters('workspaceResourceId'), 'cross-domain-investigation-extension-v1')]"},
            'displayName': {'type': 'string', 'defaultValue': 'Pivot Point'}},
        'resources': [{'type': 'Microsoft.Insights/workbooks', 'apiVersion': '2022-04-01',
            'name': "[parameters('workbookName')]", 'location': "[parameters('location')]", 'kind': 'shared',
            'properties': {'displayName': "[parameters('displayName')]", 'version': '1.0',
                'sourceId': "[parameters('workspaceResourceId')]", 'category': 'sentinel',
                'serializedData': "[replace('" + serialized.replace("'", "''") + "', '__WORKSPACE_RESOURCE_ID__', parameters('workspaceResourceId'))]"}}],
        'outputs': {'workbookResourceId': {'type': 'string', 'value': "[resourceId('Microsoft.Insights/workbooks', parameters('workbookName'))]"}}}
    write(ROOT / 'deployment' / 'workbook.template.json', json.dumps(arm, indent=2, ensure_ascii=False) + '\n')
    manifest = {'name': 'Pivot Point', 'packageVersion': '1.0.0', 'kind': 'read-only-workbook-extension',
        'upstreamCommit': '9a9e5cf33a477ebc349b5c2c013d990246b45303',
        'deploysEnabledRules': False, 'tenantValidated': False,
        'queries': {name: hashlib.sha256(text.encode()).hexdigest() for name, text in queries.items()},
        'sources': [{'table': t, 'scenario': s, 'keyRequirement': k, 'note': n} for t, s, k, n in SOURCES]}
    write(ROOT / 'deployment' / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
    for path in sorted(ROOT.rglob('*')):
        if path.is_file() and ':' not in path.name:
            mark(path)
    print(f'Built workbook, ARM template and manifest from {len(queries)} queries. No Azure calls made.')


if __name__ == '__main__':
    build()
