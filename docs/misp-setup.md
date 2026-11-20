# MISP and Shodan setup (F6, R-10)

MISP is the live intelligence source; Shodan shows what the internet sees on the lab's own public address. Neither runs in CI: both need keys, and the intelligence they return is live data that never enters the repository (`enrich/` and `exposure/` are git-ignored).

## Rules of engagement

- Shodan is asked about one address only: the student's own public IP (`OWN_PUBLIC_IP`). Never a third party's.
- The public IP is personal data. It stays in `secrets/intel.enc.yaml` (ciphertext) and `exposure/` (git-ignored); `make exposure` prints it masked. It never appears in a commit or a screenshot.
- MISP indicators are live intelligence. Screenshots show only indicators whose MISP event is TLP:CLEAR (or TLP:WHITE); anything AMBER or above is covered.
- Keys go through SOPS, like the OpenSearch password (R-02).

## 1. Run MISP (once per machine)

```bash
make misp-up      # clones misp-docker next to this repository at a pinned commit, then starts it
```

`make misp-setup` (run by `make misp-up`) does the following:
- clones `MISP/misp-docker` into `../misp-docker`, checked out at commit `27ec05e` (2026-11-04) and verified;
- copies `misp/compose.override.yaml`, which pins every image by digest (MISP core 2.5.51, modules 3.1.3, MariaDB 10.11, Valkey 7.2);
- writes `../misp-docker/.env` (mode 600): MISP on `127.0.0.1:8444` only, random database and cache passwords, and no credentials printed in the logs;
- creates a localhost certificate in `../misp-docker/certs-local/`, which `misp_pull.py` trusts as its only CA.

The first start takes two to three minutes, until `misp-core` reports healthy.

Images in use, recorded on 2026-11-20:

| Service | Image |
|---|---|
| misp-core | `ghcr.io/misp/misp-docker/misp-core:27ec05e@sha256:03c0b1d0b9e2e3c8261b987e9e911e8efec139d0ece4337285e5175b68817a31` |
| misp-nginx | `ghcr.io/misp/misp-docker/misp-nginx:27ec05e@sha256:a287c9e845d9d45127f1f5fb77df29a04f76e9f837993cc7bac7bee520c5354a` |
| misp-modules | `ghcr.io/misp/misp-docker/misp-modules:27ec05e@sha256:b83285a8ee01905fad1c89c9b8c8496595460ab57737a91886c724182673b6ba` |
| db | `ghcr.io/mariadb/mariadb:10.11@sha256:c22d749c07c6d2b3b5827074d7a54c97ebada20a69c491efef819b8c1ecaa96f` |
| redis | `ghcr.io/valkey-io/valkey:7.2@sha256:edf27a750238c2a8be56d6c365d21930926cfee23385efe88cc6df9df2c911a1` |
| mail | `ghcr.io/egos-tech/smtp:2.0.12@sha256:c7577b21872f785ffdc9f4403938322cc424055c771621586bec60a05745d312` |

## 2. First login and an API key (student, in the browser)

1. Open `https://localhost:8444`. The browser warns about the self-signed certificate; continue.
2. Log in as `admin@admin.test` with MISP's public default password `admin`. MISP then asks for a new password at once: choose a strong one and keep it in your password manager.
3. Administration, List Auth Keys:
   - delete the key MISP created at first start, which was written to the container log before printing was turned off;
   - Add authentication key, with comment `ml-ids-stack misp_pull` and **Read only** ticked. `misp_pull.py` only reads.

   Copy the key: MISP shows it once.
4. Sync Actions, Feeds:
   - Load default feed metadata;
   - tick **CIRCL OSINT Feed**, then Enable selected and Enable caching for selected;
   - edit **Feodo IP Blocklist** (abuse.ch, botnet command-and-control servers) and **blocklist.de/lists/all.txt** (addresses reported for attacks in the last 48 hours): tick Enabled and Caching enabled, and save;
   - Fetch and store all feed data.

   The fetch runs in the background for several minutes. Events appear under Event Actions, List Events; each CSV or freetext feed keeps one event, updated on every fetch.
5. Mark both feed events TLP:CLEAR, since both lists are published openly:
   - Event Actions, List Taxonomies: enable `tlp`, then open it and enable all its tags;
   - open the event of each feed (`Feodo IP Blocklist feed`, `blocklist.de/lists/all.txt feed`), click `+` next to Tags, choose the taxonomy `tlp` and the tag `tlp:clear`.

   The tag stays on the event when the feed is fetched again. `misp_pull.py` records it per indicator, and screenshots show only indicators marked clear.
6. Input Filters, List Warninglists: enable the lists of addresses that must never be treated as indicators. `misp_pull.py` asks MISP to drop every attribute on an enabled list (`enforce_warninglist`), so with none enabled that check does nothing:
   - List of RFC 1918 CIDR blocks, List of RFC 5735 CIDR blocks, List of RFC 6598 CIDR blocks, List of RFC 5771 multicast CIDR blocks;
   - List of known IPv4 public DNS resolvers;
   - List of known Akamai IP ranges, List of known Amazon AWS IP address ranges, List of known Cloudflare IP ranges, List of known Fastly IP address ranges, List of known GCP (Google Cloud Platform) IP address ranges, List of known Microsoft Azure Datacenter IP Ranges.

Feeds in use:

| Feed | Publisher | Why |
|---|---|---|
| CIRCL OSINT Feed | CIRCL | curated analyst reports; its IP indicators are from 2014 to 2020, so the 30-day age-out drops them all, which the meta file shows |
| Feodo IP Blocklist | abuse.ch | active botnet command-and-control servers: what the beacon demonstration contacts |
| blocklist.de/lists/all.txt | blocklist.de | addresses reported for scans and brute force in the last 48 hours: what the port scan demonstration comes from |

CSV and freetext feeds are stored under the local MISP organisation, so their weight in `enrichment/feeds.yml` is the one of `ADMIN`, the organisation misp-docker creates. `make misp-pull` records the date of each pull in `enrich/ioc_ip.meta.json`.

## 3. The keys, encrypted

```bash
sops edit secrets/intel.enc.yaml
```

Enter the following, then save (sops encrypts on save; no plaintext copy touches the disk):

```yaml
MISP_URL: https://localhost:8444
MISP_KEY: <the read-only MISP auth key>
MISP_CA: /home/<you>/misp-docker/certs-local/cert.pem
SHODAN_KEY: <your Shodan API key, from https://account.shodan.io>   # a free account is enough
OWN_PUBLIC_IP: <your own public IPv4 address>
```

`make secrets` (run by every target that needs them) decrypts both files into `.env.secrets`, mode 600, which `make down` deletes.

## 4. Pull, check, demonstrate

```bash
make misp-pull              # indicators into enrich/ioc_ip.yml; prints counts only
make exposure               # one Shodan lookup of the own address; prints it masked
make ti-demo DEMO_IOC=<an address from enrich/ioc_ip.yml whose event is TLP:CLEAR>
```

A free Shodan account has no credits for the host API, which answers 403. `make exposure` then asks InternetDB (`internetdb.shodan.io`), Shodan's free per-address service built on the same scans: open ports, known CVEs and tags, without banners. The snapshot names the source that answered.

With the stack up (`make up`), Logstash rereads `enrich/ioc_ip.yml` every five minutes and ingests the demo replays from `out/`. `docs/project.md` (section 6) describes the outcome rule and the evidence.
