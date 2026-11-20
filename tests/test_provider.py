import json
import logging

import pytest
import requests_mock

from octodns.provider import SupportsException
from octodns.record import Record
from octodns.zone import Zone

from octodns_nameocean import NameOceanClientException, NameOceanProvider

API = 'https://nameocean.net/api/v1'

EXPORT = {
    'zone': 'example.com',
    'records': [
        {'name': '@', 'type': 'A', 'value': '203.0.113.10'},
        {'name': '@', 'type': 'A', 'value': '203.0.113.11'},
        {'name': '@', 'type': 'AAAA', 'value': '2001:db8::1', 'ttl': '5m'},
        {'name': '@', 'type': 'MX', 'value': 'mail.example.com', 'priority': 10},
        {'name': '@', 'type': 'TXT', 'value': 'v=spf1 include:_spf.example.net ~all'},
        {'name': '@', 'type': 'TXT', 'value': 'a;b'},
        {'name': '@', 'type': 'CAA', 'value': 'letsencrypt.org', 'tag': 'issue', 'flags': 0},
        {'name': '@', 'type': 'HTTPS', 'value': '.', 'priority': 1, 'params': 'alpn=h2,h3'},
        {'name': 'www', 'type': 'CNAME', 'value': '@'},
        {'name': 'api', 'type': 'CNAME', 'value': 'lb.example.net', 'ttl': '15m'},
        {'name': '_sip._tcp', 'type': 'SRV', 'value': 'sip.example.com', 'priority': 10, 'weight': 5, 'port': 5060},
        {'name': 'sub', 'type': 'NS', 'value': 'ns1.other.net'},
        {'name': 'sub', 'type': 'NS', 'value': 'ns2.other.net'},
        {'name': 'sub', 'type': 'DS', 'value': 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
         'key_tag': 12345, 'algorithm': 13, 'digest_type': 2},
        # not octoDNS's: passed through untouched
        {'name': 'go', 'type': 'REDIRECT', 'value': 'https://example.org/', 'save_path': True},
        {'name': 'shop', 'type': 'ALIAS', 'value': 'shops.example.net'},
    ],
}


def provider(**kwargs):
    return NameOceanProvider('test', 'no_live_test', **kwargs)


def populated(m, doc=EXPORT, serial='42', **kwargs):
    m.get(f'{API}/dns/example.com/export', json=doc, headers={'X-Zone-Serial': serial})
    p = provider(**kwargs)
    zone = Zone('example.com.', [])
    assert p.populate(zone, target=True) is True
    return p, zone


def by_key(zone):
    return {(r.name, r._type): r for r in zone.records}


def test_populate_maps_every_type():
    with requests_mock.Mocker() as m:
        _, zone = populated(m)
    recs = by_key(zone)
    assert set(recs) == {
        ('', 'A'), ('', 'AAAA'), ('', 'MX'), ('', 'TXT'), ('', 'CAA'), ('', 'HTTPS'),
        ('www', 'CNAME'), ('api', 'CNAME'), ('_sip._tcp', 'SRV'), ('sub', 'NS'), ('sub', 'DS'),
    }
    assert recs[('', 'A')].values == ['203.0.113.10', '203.0.113.11']
    assert recs[('', 'A')].ttl == 3600
    assert recs[('', 'AAAA')].ttl == 300
    assert recs[('', 'MX')].values[0].exchange == 'mail.example.com.'
    assert recs[('', 'TXT')].values == ['a\\;b', 'v=spf1 include:_spf.example.net ~all']
    assert recs[('www', 'CNAME')].value == 'example.com.'
    assert recs[('api', 'CNAME')].ttl == 900
    assert recs[('_sip._tcp', 'SRV')].values[0].target == 'sip.example.com.'
    assert recs[('sub', 'NS')].values == ['ns1.other.net.', 'ns2.other.net.']
    assert recs[('sub', 'DS')].values[0].key_tag == 12345
    https = recs[('', 'HTTPS')].values[0]
    assert https.svcpriority == 1 and https.targetname == '.'
    assert https.svcparams == {'alpn': ['h2', 'h3']}


def test_missing_zone():
    with requests_mock.Mocker() as m:
        m.get(f'{API}/dns/example.com/export', status_code=404, json={'error': 'no zone'})
        assert provider().populate(Zone('example.com.', []), target=True) is False


def test_api_error_is_raised():
    with requests_mock.Mocker() as m:
        m.get(f'{API}/dns/example.com/export', status_code=401, json={'error': 'Turn on two-step login'})
        with pytest.raises(NameOceanClientException, match='401 Turn on two-step login'):
            provider().populate(Zone('example.com.', []), target=True)


def test_sync_of_the_same_zone_has_no_changes():
    with requests_mock.Mocker() as m:
        p, existing = populated(m)
        desired = Zone('example.com.', [])
        for r in existing.records:
            desired.add_record(r.copy(zone=desired))
        m.get(f'{API}/dns/example.com/export', json=EXPORT, headers={'X-Zone-Serial': '42'})
        assert p.plan(desired) is None


def apply_body(m):
    return json.loads(m.request_history[-1].text)


def test_apply_sends_the_whole_zone_once_with_the_serial():
    with requests_mock.Mocker() as m:
        m.get(f'{API}/dns/example.com/export', json=EXPORT, headers={'X-Zone-Serial': '42'})
        m.post(f'{API}/dns/example.com/apply', json={'serial': 43, 'summary': {'create': 1, 'update': 1, 'delete': 1}})
        p = provider()
        current = Zone('example.com.', [])
        p.populate(current, target=True)
        desired = Zone('example.com.', [])
        for r in current.records:
            if (r.name, r._type) == ('api', 'CNAME'):
                continue  # delete
            if (r.name, r._type) == ('', 'A'):
                r = r.copy(zone=desired)
                r.values = ['203.0.113.20']  # update
            desired.add_record(r.copy(zone=desired))
        desired.add_record(Record.new(desired, 'blog', {'type': 'A', 'ttl': 300, 'value': '198.51.100.7'}))

        plan = p.plan(desired)
        assert len(plan.changes) == 3
        p.apply(plan)

        req = m.request_history[-1]
        assert req.method == 'POST' and req.qs == {'serial': ['42']}
        body = apply_body(m)
        assert body['zone'] == 'example.com'
        rows = {(r['name'], r['type'], r['value']) for r in body['records']}
        assert ('@', 'A', '203.0.113.20') in rows
        assert ('@', 'A', '203.0.113.10') not in rows
        assert ('blog', 'A', '198.51.100.7') in rows
        assert not any(r['name'] == 'api' for r in body['records'])
        # the rest unchanged, in NameOcean's form
        assert ('www', 'CNAME', '@') in rows
        assert ('@', 'TXT', 'a;b') in rows
        assert ('@', 'MX', 'mail.example.com') in rows
        assert ('sub', 'NS', 'ns1.other.net') in rows
        https = next(r for r in body['records'] if r['type'] == 'HTTPS')
        assert (https['value'], https['priority'], https['params']) == ('.', 1, 'alpn=h2,h3')
        srv = next(r for r in body['records'] if r['type'] == 'SRV')
        assert (srv['priority'], srv['weight'], srv['port']) == (10, 5, 5060)
        # passed through
        assert ('go', 'REDIRECT', 'https://example.org/') in rows
        assert ('shop', 'ALIAS', 'shops.example.net') in rows
        assert all(r.get('ttl', '1h') in ('5m', '15m', '30m', '1h', '1d') for r in body['records'] if r['type'] != 'REDIRECT')


def test_records_octodns_ignores_are_kept():
    with requests_mock.Mocker() as m:
        m.get(f'{API}/dns/example.com/export', json=EXPORT, headers={'X-Zone-Serial': '7'})
        m.post(f'{API}/dns/example.com/apply', json={'serial': 8})
        p = provider()
        current = Zone('example.com.', [])
        p.populate(current, target=True)
        desired = Zone('example.com.', [])
        desired.add_record(Record.new(desired, 'blog', {'type': 'A', 'ttl': 300, 'value': '198.51.100.7'}))
        for r in current.records:
            if r._type != 'TXT':
                desired.add_record(r.copy(zone=desired))
        # TXT left out of desired but excluded from the plan: must not be deleted
        plan = p.plan(desired)
        plan.changes = [c for c in plan.changes if c.record._type != 'TXT']
        p.apply(plan)
        rows = {(r['name'], r['type'], r['value']) for r in apply_body(m)['records']}
        assert ('@', 'TXT', 'a;b') in rows


def test_ttls_are_rounded_to_nameocean_values(caplog):
    with requests_mock.Mocker() as m:
        m.get(f'{API}/dns/example.com/export', json={'zone': 'example.com', 'records': []}, headers={'X-Zone-Serial': '1'})
        m.post(f'{API}/dns/example.com/apply', json={'serial': 2})
        p = provider(strict_supports=False)
        desired = Zone('example.com.', [])
        desired.add_record(Record.new(desired, 'a', {'type': 'A', 'ttl': 600, 'value': '192.0.2.1'}))
        desired.add_record(Record.new(desired, 'b', {'type': 'A', 'ttl': 7200, 'value': '192.0.2.2'}))
        desired.add_record(Record.new(desired, 'c', {'type': 'TXT', 'ttl': 30, 'value': 'x'}))
        with caplog.at_level(logging.WARNING):
            p.apply(p.plan(desired))
        ttls = {r['name']: r['ttl'] for r in apply_body(m)['records']}
        assert ttls == {'a': '5m', 'b': '1h', 'c': '30'}
        assert 'TTL 600 not supported' in caplog.text


def test_unsupported_ttl_is_an_error_when_strict():
    with requests_mock.Mocker() as m:
        m.get(f'{API}/dns/example.com/export', json={'zone': 'example.com', 'records': []}, headers={'X-Zone-Serial': '1'})
        p = provider()
        desired = Zone('example.com.', [])
        desired.add_record(Record.new(desired, 'a', {'type': 'A', 'ttl': 600, 'value': '192.0.2.1'}))
        with pytest.raises(SupportsException):
            p.plan(desired)


def test_new_zone_is_created_then_applied():
    with requests_mock.Mocker() as m:
        m.get(f'{API}/dns/example.com/export', status_code=404, json={'error': 'no zone'})
        m.post(f'{API}/dns', json={'name': 'example.com'})
        m.post(f'{API}/dns/example.com/apply', json={'serial': 1})
        p = provider()
        desired = Zone('example.com.', [])
        desired.add_record(Record.new(desired, '', {'type': 'A', 'ttl': 3600, 'value': '192.0.2.1'}))
        p.apply(p.plan(desired))
        methods = [(r.method, r.path) for r in m.request_history]
        assert ('post', '/api/v1/dns') in [(a.lower(), b) for a, b in methods]
        assert m.request_history[-1].qs == {}
        assert apply_body(m)['records'] == [{'name': '@', 'type': 'A', 'ttl': '1h', 'value': '192.0.2.1'}]


def test_conflict_is_reported():
    with requests_mock.Mocker() as m:
        m.get(f'{API}/dns/example.com/export', json={'zone': 'example.com', 'records': []}, headers={'X-Zone-Serial': '1'})
        m.post(f'{API}/dns/example.com/apply', status_code=409,
               json={'error': 'The zone changed since the plan (serial 1, now 2). Run the plan again.'})
        p = provider()
        desired = Zone('example.com.', [])
        desired.add_record(Record.new(desired, 'a', {'type': 'A', 'ttl': 300, 'value': '192.0.2.1'}))
        with pytest.raises(NameOceanClientException, match='409 The zone changed'):
            p.apply(p.plan(desired))


def test_multiple_srv_values_keep_the_first(caplog):
    with requests_mock.Mocker() as m:
        m.get(f'{API}/dns/example.com/export', json={'zone': 'example.com', 'records': []}, headers={'X-Zone-Serial': '1'})
        m.post(f'{API}/dns/example.com/apply', json={'serial': 2})
        p = provider(strict_supports=False)
        desired = Zone('example.com.', [])
        desired.add_record(Record.new(desired, '_x._tcp', {'type': 'SRV', 'ttl': 300, 'values': [
            {'priority': 1, 'weight': 1, 'port': 1, 'target': 'a.example.com.'},
            {'priority': 2, 'weight': 1, 'port': 1, 'target': 'b.example.com.'},
        ]}))
        p.apply(p.plan(desired))
        srv = [r for r in apply_body(m)['records'] if r['type'] == 'SRV']
        assert len(srv) == 1 and srv[0]['value'] == 'a.example.com'
