'''octoDNS provider for NameOcean DNS (https://nameocean.net).

Reads a zone with ``GET /api/v1/dns/{zone}/export`` and writes it with
``POST /api/v1/dns/{zone}/apply``: every sync is one transaction on NameOcean's
side, and it is refused (409) if someone changed the zone after octoDNS read it.
Records octoDNS can't express (HTTP REDIRECT records, ALIAS below the apex) are
read back and sent again unchanged, so a sync never deletes them.
'''

import logging
from collections import defaultdict

from requests import Session

from octodns import __version__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Delete, Record

__version__ = __VERSION__ = '0.1.0'

API_URL = 'https://nameocean.net/api/v1'

# NameOcean's TTLs: these values only (TXT also 30 s, for ACME-style records)
TTLS = {300: '5m', 900: '15m', 1800: '30m', 3600: '1h', 86400: '1d'}
TXT_TTLS = {30: '30', **TTLS}
SECONDS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
DEFAULT_TTL = '1h'

# one record per name on NameOcean
ONE_PER_NAME = ('CNAME', 'ALIAS', 'SRV')


class NameOceanClientException(ProviderException):
    pass


class NameOceanClient:
    def __init__(self, token, url=API_URL, timeout=30):
        self.url = url.rstrip('/')
        self.timeout = timeout
        self._session = Session()
        self._session.headers.update(
            {
                'Authorization': f'Bearer {token}',
                'User-Agent': f'octodns/{octodns_version} octodns-nameocean/{__VERSION__}',
            }
        )

    def _request(self, method, path, **kwargs):
        resp = self._session.request(
            method, f'{self.url}{path}', timeout=self.timeout, **kwargs
        )
        if resp.status_code >= 400 and resp.status_code != 404:
            try:
                message = resp.json().get('error') or resp.text
            except ValueError:
                message = resp.text
            raise NameOceanClientException(
                f'{method} {path}: {resp.status_code} {message}'
            )
        return resp

    def export(self, zone):
        '''The zone as a NameOcean zone document plus its serial, or (None, None).'''
        resp = self._request('GET', f'/dns/{zone}/export', params={'output': 'json'})
        if resp.status_code == 404:
            return None, None
        return resp.json(), resp.headers.get('X-Zone-Serial')

    def create_zone(self, zone):
        resp = self._request('POST', '/dns', json={'name': zone})
        if resp.status_code == 404:
            raise NameOceanClientException(f'POST /dns: 404 {resp.text}')
        return resp.json()

    def apply(self, zone, doc, serial=None):
        params = {'serial': serial} if serial else {}
        resp = self._request('POST', f'/dns/{zone}/apply', params=params, json=doc)
        if resp.status_code == 404:
            raise NameOceanClientException(f'POST /dns/{zone}/apply: 404 {resp.text}')
        return resp.json()


def _seconds(ttl):
    ttl = str(ttl or DEFAULT_TTL).strip().lower()
    if ttl[-1] in SECONDS:
        return int(ttl[:-1]) * SECONDS[ttl[-1]]
    return int(ttl)


def _closest(ttl, allowed):
    return min(allowed, key=lambda t: (abs(t - ttl), t))


class NameOceanProvider(BaseProvider):
    '''
    NameOcean DNS provider.

    providers:
      nameocean:
        class: octodns_nameocean.NameOceanProvider
        # API key with dns:read and dns:write (Dashboard -> API)
        token: env/NAMEOCEAN_API_KEY
    '''

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = False
    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'ALIAS',
            'CAA',
            'CNAME',
            'DS',
            'HTTPS',
            'MX',
            'NS',
            'SRV',
            'SVCB',
            'TXT',
        )
    )

    def __init__(self, id, token, url=API_URL, timeout=30, *args, **kwargs):
        self.log = logging.getLogger(f'NameOceanProvider[{id}]')
        self.log.debug('__init__: id=%s url=%s', id, url)
        super().__init__(id, *args, **kwargs)
        self._client = NameOceanClient(token, url, timeout)
        # zone name -> (document, serial) from the last populate
        self._exports = {}

    # --- reading -------------------------------------------------------------

    def _managed(self, rec):
        '''Whether octoDNS owns a NameOcean record (the rest is passed through).'''
        if rec['type'] not in self.SUPPORTS:
            return False
        if rec['type'] == 'ALIAS' and rec['name'] != '@':
            return False
        return True

    @staticmethod
    def _fqdn(value, zone):
        if value == '@':
            return zone + '.'
        if value == '.':
            return '.'
        return value.rstrip('.') + '.'

    def _data(self, _type, recs, zone):
        ttl = _seconds(recs[0].get('ttl'))
        fq = lambda v: self._fqdn(v, zone)  # noqa: E731
        if _type in ('A', 'AAAA'):
            return {'ttl': ttl, 'values': [r['value'] for r in recs]}
        if _type in ('CNAME', 'ALIAS'):
            return {'ttl': ttl, 'value': fq(recs[0]['value'])}
        if _type == 'NS':
            return {'ttl': ttl, 'values': [fq(r['value']) for r in recs]}
        if _type == 'MX':
            return {
                'ttl': ttl,
                'values': [
                    {'preference': r.get('priority', 10), 'exchange': fq(r['value'])}
                    for r in recs
                ],
            }
        if _type == 'SRV':
            return {
                'ttl': ttl,
                'values': [
                    {
                        'priority': r['priority'],
                        'weight': r['weight'],
                        'port': r['port'],
                        'target': fq(r['value']),
                    }
                    for r in recs
                ],
            }
        if _type == 'CAA':
            return {
                'ttl': ttl,
                'values': [
                    {'flags': r.get('flags', 0), 'tag': r['tag'], 'value': r['value']}
                    for r in recs
                ],
            }
        if _type == 'DS':
            return {
                'ttl': ttl,
                'values': [
                    {
                        'key_tag': r['key_tag'],
                        'algorithm': r['algorithm'],
                        'digest_type': r['digest_type'],
                        'digest': r['value'],
                    }
                    for r in recs
                ],
            }
        if _type in ('HTTPS', 'SVCB'):
            value_type = Record.registered_types()[_type]._value_type
            values = []
            for r in recs:
                text = f"{r.get('priority', 1)} {fq(r['value'])}"
                if r.get('params'):
                    text += ' ' + r['params']
                values.append(value_type.from_rdata_text(text))
            return {'ttl': ttl, 'values': values}
        if _type == 'TXT':
            return {
                'ttl': ttl,
                'values': [r['value'].replace(';', '\\;') for r in recs],
            }
        raise NameOceanClientException(f'unexpected type {_type}')

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )
        name = zone.name.rstrip('.')
        doc, serial = self._client.export(name)
        if doc is None:
            self._exports[name] = (None, None)
            self.log.info('populate:   zone %s does not exist', name)
            return False
        self._exports[name] = (doc, serial)

        groups = defaultdict(list)
        for rec in doc.get('records', []):
            if self._managed(rec):
                groups[(rec['name'], rec['type'])].append(rec)

        before = len(zone.records)
        for (rname, _type), recs in groups.items():
            record = Record.new(
                zone,
                '' if rname == '@' else rname,
                {'type': _type, **self._data(_type, recs, name)},
                source=self,
                lenient=lenient,
            )
            zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records, exists=True',
            len(zone.records) - before,
        )
        return True

    # --- planning ------------------------------------------------------------

    def _process_desired_zone(self, desired):
        for record in desired.records:
            changed = None
            allowed = TXT_TTLS if record._type == 'TXT' else TTLS
            if record._type in self.SUPPORTS and record.ttl not in allowed:
                ttl = _closest(record.ttl, allowed)
                self.supports_warn_or_except(
                    f'TTL {record.ttl} not supported for {record.fqdn}, '
                    f'NameOcean takes {", ".join(str(t) for t in sorted(allowed))}',
                    f'using {ttl}',
                )
                changed = record.copy()
                changed.ttl = ttl
            if record._type == 'SRV' and len(record.values) > 1:
                self.supports_warn_or_except(
                    f'{record.fqdn} has {len(record.values)} SRV values, '
                    'NameOcean keeps one SRV record per name',
                    'using the first value',
                )
                changed = changed or record.copy()
                changed.values = changed.values[:1]
            if record._type == 'TXT' and any('"' in v for v in record.values):
                self.supports_warn_or_except(
                    f'{record.fqdn} has a TXT value with a double quote',
                    'omitting record',
                )
                desired.remove_record(record)
                continue
            if record._type == 'CAA' and any(
                v.flags not in (0, 128) for v in record.values
            ):
                self.supports_warn_or_except(
                    f'{record.fqdn} has CAA flags other than 0 and 128',
                    'omitting record',
                )
                desired.remove_record(record)
                continue
            if changed is not None:
                desired.add_record(changed, replace=True)
        return super()._process_desired_zone(desired)

    # --- writing -------------------------------------------------------------

    def _rows(self, record, zone):
        '''An octoDNS record as NameOcean zone document records.'''
        name = record.name or '@'
        _type = record._type
        allowed = TXT_TTLS if _type == 'TXT' else TTLS
        base = {'name': name, 'type': _type, 'ttl': allowed[record.ttl]}

        def host(value):
            value = value.rstrip('.')
            return '@' if value == zone else value

        if _type in ('CNAME', 'ALIAS'):
            return [{**base, 'value': host(record.value)}]
        rows = []
        for v in record.values:
            if _type in ('A', 'AAAA'):
                rows.append({**base, 'value': str(v)})
            elif _type == 'NS':
                rows.append({**base, 'value': host(v)})
            elif _type == 'MX':
                rows.append({**base, 'value': host(v.exchange), 'priority': v.preference})
            elif _type == 'SRV':
                rows.append(
                    {
                        **base,
                        'value': host(v.target),
                        'priority': v.priority,
                        'weight': v.weight,
                        'port': v.port,
                    }
                )
            elif _type == 'CAA':
                rows.append({**base, 'value': v.value, 'tag': v.tag, 'flags': v.flags})
            elif _type == 'DS':
                rows.append(
                    {
                        **base,
                        'value': v.digest,
                        'key_tag': v.key_tag,
                        'algorithm': v.algorithm,
                        'digest_type': v.digest_type,
                    }
                )
            elif _type in ('HTTPS', 'SVCB'):
                priority, target, *params = v.to_rdata_text().split(' ', 2)
                target = '.' if target == '.' else host(target)
                rows.append(
                    {
                        **base,
                        'value': target,
                        'priority': int(priority),
                        'params': params[0] if params else '',
                    }
                )
            elif _type == 'TXT':
                rows.append({**base, 'value': v.replace('\\;', ';')})
        return rows

    def _apply(self, plan):
        desired = plan.desired
        name = desired.name.rstrip('.')
        self.log.debug('_apply: zone=%s, len(changes)=%d', name, len(plan.changes))

        doc, serial = self._exports.get(name, (None, None))
        if not plan.exists:
            self.log.info('_apply:   creating zone %s', name)
            self._client.create_zone(name)
            doc, serial = None, None

        # start from what was read, then apply exactly the planned changes, so
        # records octoDNS ignores or can't express are kept as they are
        final = {}
        if plan.existing is not None:
            for record in plan.existing.records:
                final[(record.name, record._type)] = record
        for change in plan.changes:
            record = change.record
            key = (record.name, record._type)
            if isinstance(change, Delete):
                final.pop(key, None)
            else:
                final[key] = change.new

        records = [
            r for r in (doc or {}).get('records', []) if not self._managed(r)
        ]
        for record in sorted(final.values(), key=lambda r: (r.name, r._type)):
            records.extend(self._rows(record, name))

        result = self._client.apply(
            name, {'zone': name, 'records': records}, serial
        )
        summary = result.get('summary') or {}
        self.log.info(
            '_apply:   zone %s now at serial %s (%s)',
            name,
            result.get('serial'),
            ', '.join(f'{k} {v}' for k, v in summary.items()) or 'applied',
        )
        self._exports.pop(name, None)
