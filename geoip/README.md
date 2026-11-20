# GeoIP databases (R-10)

These databases give the country and autonomous system of public addresses. `pipelines/threat-intel.conf` adds both to every ML-IDS and Suricata record.

| File | Content | Published |
|---|---|---|
| `dbip-country-lite-2026-11.mmdb.gz` | IP to Country Lite | 2026-11-01 |
| `dbip-asn-lite-2026-11.mmdb.gz` | IP to ASN Lite | 2026-11-01 |

Source: [DB-IP](https://db-ip.com) Lite databases, `https://download.db-ip.com/free/`, licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/). IP Geolocation by DB-IP.

The files are committed compressed, because DB-IP keeps only the last few months online; this way a later clone still builds. `SHA256SUMS` holds their hashes. `make geoip` (run by `make up`) and the pipeline tests unpack the files only after the hashes match.

To refresh the databases, at most monthly and at least 14 days after publication (cooldown, R-04):

```bash
M=2026-12
for k in country asn; do curl -fsSLO "https://download.db-ip.com/free/dbip-$k-lite-$M.mmdb.gz"; done
sha256sum dbip-*-lite-$M.mmdb.gz > SHA256SUMS
```

Then:

1. Remove the old files.
2. Set `GEOIP_MONTH` in the Makefile.
3. Update the table above.
