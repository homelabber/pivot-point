"""Local contract tests and synthetic behavioral specifications, not a KQL engine."""
import base64
import hashlib
import importlib.util
import json
import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('builder', ROOT / 'tools' / 'build.py')
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
START = datetime(2026, 11, 10, tzinfo=timezone.utc)
APP = '11111111-1111-1111-1111-111111111111'
OTHER = '22222222-2222-2222-2222-222222222222'


def walk(value):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def candidate_counts(consents, events, start=START, end=START + timedelta(days=1), minimum=5):
    """Executable specification for the query's baseline and sequence contracts."""
    historical = {app.lower() for time, app in events if start - timedelta(days=14) <= time < start}
    results = []
    for change, app in consents:
        app = app.lower()
        if not (start <= change <= end) or app in historical:
            continue
        current = [time for time, key in events if key.lower() == app and start <= time <= end
                   and change <= time <= change + timedelta(hours=24)]
        if len(current) >= minimum:
            results.append((app, len(current)))
    return results


class PackageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workbook = json.loads((ROOT / 'workbook' / 'cross-domain-extension.workbook.json').read_text(encoding='utf-8'))
        cls.arm = json.loads((ROOT / 'deployment' / 'workbook.template.json').read_text(encoding='utf-8'))
        cls.manifest = json.loads((ROOT / 'deployment' / 'manifest.json').read_text(encoding='utf-8'))
        cls.queries = {p.stem: p.read_text(encoding='utf-8') for p in (ROOT / 'queries').glob('*.kql')}

    def test_only_workbook_is_deployed(self):
        self.assertEqual([r['type'] for r in self.arm['resources']], ['Microsoft.Insights/workbooks'])
        self.assertFalse(self.manifest['deploysEnabledRules'])
        self.assertFalse(self.manifest['tenantValidated'])

    def test_arm_serialized_workbook_round_trip(self):
        value = self.arm['resources'][0]['properties']['serializedData']
        prefix = "[replace('"
        suffix = "', '__WORKSPACE_RESOURCE_ID__', parameters('workspaceResourceId'))]"
        self.assertTrue(value.startswith(prefix) and value.endswith(suffix))
        embedded = value[len(prefix):-len(suffix)].replace("''", "'")
        self.assertEqual(json.loads(embedded), self.workbook)
        resolved = json.loads(embedded.replace('__WORKSPACE_RESOURCE_ID__', '/subscriptions/test/resourceGroups/test/providers/Microsoft.OperationalInsights/workspaces/test'))
        self.assertNotIn('__WORKSPACE_RESOURCE_ID__', json.dumps(resolved))

    def test_pivot_point_branding_is_consistent(self):
        self.assertEqual(self.manifest['name'], 'Pivot Point')
        self.assertEqual(self.arm['parameters']['displayName']['defaultValue'], 'Pivot Point')
        self.assertTrue(self.workbook['items'][0]['content']['json'].startswith('# Pivot Point\n'))
        self.assertTrue((ROOT / 'README.md').read_text(encoding='utf-8').startswith('# Pivot Point\n'))

    def test_template_id_is_stable_and_workspace_specific(self):
        default = self.arm['parameters']['workbookName']['defaultValue']
        self.assertIn('guid(', default)
        self.assertIn("parameters('workspaceResourceId')", default)

    def test_all_query_sources_embedded_exactly_once(self):
        embedded = [n['query'] for n in walk(self.workbook) if isinstance(n.get('query'), str)]
        self.assertCountEqual(embedded, self.queries.values())
        self.assertEqual(len(embedded), 6)

    def test_query_hashes_match_sources(self):
        expected = {n: hashlib.sha256(q.encode()).hexdigest() for n, q in self.queries.items()}
        self.assertEqual(expected, self.manifest['queries'])

    def test_every_placeholder_has_declared_parameter(self):
        parameters = next(n['parameters'] for n in walk(self.workbook) if n.get('version') == 'KqlParameterItem/1.0')
        names = {p['name'] for p in parameters}
        for query in self.queries.values():
            used = set(re.findall(r'\{([A-Za-z]\w*):[^}]+\}', query))
            self.assertFalse(used - names)
            self.assertNotIn('{{StartTimeISO}}', query)

    def test_text_inputs_are_base64_encoded(self):
        for name in ('Entity', 'AppId', 'MessageId', 'MinimumEvents'):
            for query in self.queries.values():
                for formatter in re.findall(r'\{' + name + r':([^}]+)\}', query):
                    self.assertEqual(formatter, 'base64')
        self.assertTrue(any('base64_decode_tostring' in q for q in self.queries.values()))

    def test_hostile_input_cannot_escape_encoded_literal(self):
        for text in ("o'brien@example.com", "'; union SecurityAlert //", '"\\\n{}', '测试@example.com'):
            encoded = base64.b64encode(text.encode()).decode()
            self.assertRegex(encoded, r'^[A-Za-z0-9+/=]+$')
            self.assertEqual(base64.b64decode(encoded).decode(), text)

    def test_optional_panels_default_off_and_are_conditional(self):
        parameters = next(n['parameters'] for n in walk(self.workbook) if n.get('version') == 'KqlParameterItem/1.0')
        for name in ('ShowEmail', 'ShowData'):
            self.assertEqual(next(p['value'] for p in parameters if p['name'] == name), '0')
            matches = [n for n in walk(self.workbook) if n.get('conditionalVisibility', {}).get('parameterName') == name]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]['conditionalVisibility']['value'], '1')

    def test_no_time_picker_clips_baselines(self):
        panels = [n for n in walk(self.workbook) if n.get('version') == 'KqlItem/1.0']
        for panel in panels:
            self.assertNotIn('timeContextFromParameter', panel)
            self.assertEqual(panel['timeContext']['durationMs'], 90 * 86400000)
            self.assertEqual(panel['crossComponentResources'], ['{Workspace}'])

    def test_out_of_envelope_evidence_is_guarded(self):
        for name, query in self.queries.items():
            if name != 'investigation-scope':
                self.assertIn('| where StartTime >= ago(30d) and EndTime <= now() + 5m and StartTime < EndTime', query)
        self.assertIn('Unsupported period', self.queries['investigation-scope'])

    def test_missing_sources_have_typed_empty_fallback(self):
        for name, query in self.queries.items():
            if name != 'investigation-scope':
                self.assertIn('union isfuzzy=true', query)
                self.assertIn('datatable(', query)
                self.assertNotIn('datatable(x:int)[1]', query)

    def test_readiness_covers_every_source_table(self):
        tables = {s['table'] for s in self.manifest['sources']}
        expected = {'AuditLogs', 'AADServicePrincipalSignInLogs', 'CloudAppEvents', 'SecurityAlert',
                    'SecurityIncident', 'EmailEvents', 'UrlClickEvents', 'OfficeActivity',
                    'MicrosoftPurviewInformationProtection'}
        self.assertEqual(tables, expected)
        readiness = self.queries['scenario-readiness']
        self.assertIn('UsableKeyEvents', readiness)
        self.assertIn('HistoricalEvents', readiness)
        self.assertIn('Unavailable or inaccessible', readiness)
        self.assertEqual(readiness, BUILDER.readiness())

    def test_baseline_strictly_precedes_start(self):
        oauth = self.queries['oauth-consent-followed-by-new-app-activity']
        historical = oauth.split('let HistoricalApps =', 1)[1].split('let NovelActivity', 1)[0]
        self.assertIn('ActivityTime < StartTime', historical)
        self.assertNotIn('EndTime', historical)
        self.assertIn('join kind=leftanti HistoricalApps on AppKey', oauth)

    def test_oauth_linkage_does_not_join_on_ip(self):
        oauth = self.queries['oauth-consent-followed-by-new-app-activity']
        self.assertIn('join kind=inner NovelActivity on AppKey', oauth)
        self.assertIn('array_length(Apps) == 1', oauth)
        self.assertIn('ActivityTime >= ChangeTime', oauth)
        self.assertNotRegex(oauth, r'join[^\n]+(?:Ip|IP)')
        self.assertIn('Target.type) =~ \'ServicePrincipal\'', oauth)

    def test_related_incidents_require_nonempty_exact_entity(self):
        query = self.queries['related-incidents']
        self.assertIn('where isnotempty(SelectedEntity)', query)
        self.assertNotIn('contains SelectedEntity', query)
        self.assertIn('$left.AlertId == $right.IncidentAlertId', query)
        self.assertIn('arg_max(TimeGenerated, *) by IncidentName', query)

    def test_email_uses_message_and_recipient_not_ip(self):
        query = self.queries['email-evidence']
        self.assertIn('$left.Recipient == $right.ClickAccount', query)
        self.assertIn('ClickTime >= MessageTime', query)
        self.assertIn('isempty(SelectedMessage) and isnotempty(SelectedEntity)', query)

    def test_purview_does_not_imply_exfiltration(self):
        self.assertIn('not proof of exfiltration', self.queries['data-impact'])
        self.assertIn('Account == SelectedEntity', self.queries['data-impact'])

    def test_sentinel_sources_use_timegenerated_not_xdr_timestamp(self):
        for query in self.queries.values():
            self.assertNotRegex(query, r'\bTimestamp\b')

    def test_empty_results_are_not_described_as_safe(self):
        panels = [n for n in walk(self.workbook) if n.get('version') == 'KqlItem/1.0']
        for panel in panels:
            self.assertIn('not a safety or detection verdict', panel['noDataMessage'])


class BehavioralSpecificationTests(unittest.TestCase):
    def events(self, app=APP, offset=1, count=5):
        return [(START + timedelta(hours=offset, minutes=i), app) for i in range(count)]

    def test_new_app_is_not_eliminated_by_its_own_current_activity(self):
        self.assertEqual(candidate_counts([(START, APP)], self.events()), [(APP, 5)])

    def test_preexisting_app_is_excluded(self):
        events = self.events() + [(START - timedelta(seconds=1), APP)]
        self.assertEqual(candidate_counts([(START, APP)], events), [])

    def test_baseline_lower_boundary_is_included(self):
        events = self.events() + [(START - timedelta(days=14), APP)]
        self.assertEqual(candidate_counts([(START, APP)], events), [])

    def test_old_event_outside_baseline_does_not_exclude(self):
        events = self.events() + [(START - timedelta(days=14, seconds=1), APP)]
        self.assertEqual(candidate_counts([(START, APP)], events), [(APP, 5)])

    def test_activity_at_start_is_current_not_history(self):
        self.assertEqual(candidate_counts([(START, APP)], [(START, APP)], minimum=1), [(APP, 1)])

    def test_burst_before_consent_is_not_counted(self):
        self.assertEqual(candidate_counts([(START + timedelta(hours=2), APP)], self.events()), [])

    def test_different_app_even_on_same_network_is_not_linked(self):
        self.assertEqual(candidate_counts([(START, OTHER)], self.events()), [])

    def test_threshold_is_applied(self):
        self.assertEqual(candidate_counts([(START, APP)], self.events(count=4)), [])

    def test_after_sequence_window_is_excluded(self):
        self.assertEqual(candidate_counts([(START, APP)], self.events(offset=25), end=START + timedelta(days=2)), [])

    def test_empty_sources_do_not_create_candidates(self):
        self.assertEqual(candidate_counts([(START, APP)], []), [])
        self.assertEqual(candidate_counts([], self.events()), [])

    def test_app_id_is_case_normalized(self):
        app = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.assertEqual(candidate_counts([(START, app.upper())], self.events(app=app)), [(app, 5)])


if __name__ == '__main__':
    unittest.main()
