# octodns-nameocean

An [octoDNS](https://github.com/octodns/octodns) provider for [NameOcean](https://nameocean.net) DNS. You keep your zones in YAML in git, review changes in pull requests, and sync them to NameOcean's nameservers (ns1–ns4.nameocean.net).

## Install

```sh
pip install octodns octodns-nameocean
```

## Configure

Create an [API key](https://nameocean.net/dashboard/api/) with `dns:read` and `dns:write`, and limit it to your CI's IP address if you can. API keys need [two-step login](https://nameocean.net/dashboard/security/) on the account.

```yaml
# config/production.yaml
providers:
  config:
    class: octodns.provider.yaml.YamlProvider
    directory: ./zones
    default_ttl: 3600
  nameocean:
    class: octodns_nameocean.NameOceanProvider
    token: env/NAMEOCEAN_API_KEY

zones:
  example.com.:
    sources:
      - config
    targets:
      - nameocean
```

Start from what is live now:

```sh
export NAMEOCEAN_API_KEY=no_live_…
octodns-dump --config-file config/production.yaml --output-dir zones example.com. nameocean
```

Then plan and apply:

```sh
octodns-sync --config-file config/production.yaml          # shows the plan
octodns-sync --config-file config/production.yaml --doit   # applies it
```

## How it works

- The provider reads a zone with one `GET /api/v1/dns/{zone}/export` call. It writes the whole result with one `POST /api/v1/dns/{zone}/apply`. NameOcean applies it in a **single transaction**: if one record is refused, nothing changes.
- The apply carries the zone serial from the read. If someone changed the zone in between (in the dashboard, or with another tool), NameOcean answers `409` and nothing is written. Run the sync again.
- Records octoDNS can't describe stay exactly as they are and a sync never deletes them. These are HTTP `REDIRECT` records and `ALIAS` records below the apex. The provider also leaves alone records NameOcean manages itself, such as ACME challenges.
- If the zone does not exist in your account, the provider creates it.

## Supported records

`A`, `AAAA`, `ALIAS` (apex), `CAA`, `CNAME`, `DS`, `HTTPS`, `MX`, `NS` (subdomain delegation), `SRV`, `SVCB`, `TXT`.

NameOcean limits:

- **TTLs** are 300, 900, 1800, 3600 or 86400 seconds (TXT records may also use 30). With the default `strict_supports: true`, any other TTL is an error. With `strict_supports: false` it is rounded to the nearest allowed value (the shorter one on a tie), with a warning.
- **One SRV record per name.** With `strict_supports: false`, only the first value is kept.
- **CAA** flags are 0 or 128, and **TXT** values can't contain double quotes.
- The zone's own NS records are NameOcean's nameservers and are not managed (`SUPPORTS_ROOT_NS = False`).
- Geo and dynamic records are not supported.

## Options

| Option | Default | |
|---|---|---|
| `token` | — | API key (`env/NAMEOCEAN_API_KEY`) |
| `url` | `https://nameocean.net/api/v1` | API base URL |
| `timeout` | `30` | Seconds per request |

## Development

```sh
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

## License

MIT
