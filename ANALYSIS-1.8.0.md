# Analyse VPS Manager v1.8.0

Volledige code-analyse na de 1.8.0 release: bugs, security, performance, ontbrekende zaken en architectuur. Alle bevindingen zijn geverifieerd in de code met bestand- en regelverwijzingen.

> **Status (v1.8.1):** geïmplementeerd in deze branch — 1.1 (manager-data backup), 1.2 (TOTP-replay), 1.3 (corrupt config logging + `.corrupt` bewaren), 1.4 (json_escape NAS-script), 1.5 (find|while foutafhandeling), 1.7 (realpath in file-routes incl. symlink-delete), 1.8 (lege catch, IPv6-whitelist client+server, escHtml-duplicaat, palette-escaping), 2.3 (HSTS), 2.4 (sessie-regeneratie), 3.1 (parallelle HTTP-checks), 3.2 (cache-sweep), gap #2-#6 deels (CI-workflow met syntax/kritieke lint, versie-pinning, `/health`, logrotate-config in `deploy/`). De CDN-claim in de README is gecorrigeerd (Chart.js komt van jsdelivr; Google Fonts op de loginpagina is verwijderd — het font stond al lokaal). Nog open: 1.6 (cronjob TOCTOU), 2.2/2.6 (inline JS uitfaseren, 2FA recovery codes), 2.5 (API rate limiting), tests, blueprints, WSGI-server.

**Algemeen beeld:** de security-basis is na 1.8.0 goed op orde (CSP, security headers, login rate limiting, timing-safe vergelijkingen, atomic writes, CSRF, sessie-flags). De grootste resterende risico's zitten niet in de code zelf, maar in de randvoorwaarden: de manager-data wordt niet geback-upt, er zijn geen tests, en de app draait op de Flask dev-server.

---

## 1. Bugs (geverifieerd)

### 1.1 Manager-data wordt niet geback-upt — **HOOG**
`web/vps-backup.sh:25` — `SKIP_DIRS` slaat de hele manager-directory over met als reden "redeployable from git". Maar `data/` staat in `.gitignore` en bevat:
- `config.json` (TOTP-secret, SMTP-wachtwoord, webhook-secret, alle instellingen)
- `.secret_key` (Flask sessie-key)
- VAPID-keys (alle push-subscriptions worden waardeloos zonder)
- notificatie-historie en audit log

Bij disk failure ben je het 2FA-secret kwijt (lockout, alleen via SSH te herstellen) en moeten alle apparaten opnieuw push-notificaties activeren.

**Fix:** voeg `data/` van de manager expliciet toe aan de backup (aparte tarball in `$BACKUP_DIR/configs/`).

### 1.2 TOTP-code is herbruikbaar binnen het tijdvenster — MIDDEL
`web/app.py:1415` en `web/app.py:5814` — `totp.verify(code, valid_window=1)` zonder bij te houden welke code het laatst gebruikt is. Een afgekeken/onderschepte code is ±60–90 seconden herbruikbaar. Standaardmitigatie: sla de laatst geaccepteerde tijdstap op en weiger codes die niet nieuwer zijn.

### 1.3 Corrupt `config.json` wordt stil genegeerd — MIDDEL
`web/config.py:116-117` — bij `JSONDecodeError`/`OSError` valt `load_config()` zonder enige log of waarschuwing terug op defaults. De app start dan "vers" op (wachtwoord-hash weg → env/generated password, instellingen weg) zonder dat duidelijk is waarom. Log minimaal een error en bewaar het corrupte bestand als `.corrupt`.

### 1.4 Kapotte JSON-escaping in NAS-script — MIDDEL
`web/nas-pull-backup.sh:40` — `json_escape()` escapet alleen `\` en `"` via sed; newlines en control-characters niet. Details met meerdere regels (bijv. rsync-output bij een fout) leveren ongeldige JSON op, waardoor de webhook-melding stilletjes faalt — juist op het moment dat de backup-status het belangrijkst is. `vps-backup.sh` doet dit wél goed via `python3 json.dumps`; gebruik dezelfde aanpak (Python is niet altijd aanwezig op Synology — `jq` of een sed die `\n`/`\t`/`\r` meeneemt kan ook).

### 1.5 Fouten in `find | while`-loops verdwijnen — LAAG
`web/vps-backup.sh` (.env- en config-secties rond regel 162-172) — fouten binnen een `| while read`-subshell worden niet door `set -e`/de ERR-trap gezien. Een mislukte `cp` van een `.env`-bestand blijft onopgemerkt en de backup rapporteert "success".

### 1.6 Cronjob-bewerkingen hebben een TOCTOU-race — LAAG
`web/app.py` (cronjobs edit/delete, rond regel 6385-6444) — tussen `crontab -l` en `crontab -` kan de crontab extern wijzigen; de index `line_num` wijst dan naar de verkeerde regel of valt buiten bereik. Voor een single-admin tool acceptabel, maar een her-check van de regelinhoud vóór het schrijven is een goedkope verzekering.

### 1.7 File browser: check op realpath, toegang via abspath — LAAG
`web/app.py:4850` (`files_list` e.a.) — `is_path_allowed()` resolvet symlinks correct via `realpath` (`app.py:3274`), maar de daadwerkelijke toegang gebruikt daarna `os.path.abspath(path)`. Een symlink die ná de check wordt omgewisseld kan in theorie ontsnappen. Gebruik consequent het resultaat van `os.path.realpath()` voor zowel de check als de toegang.

### 1.8 Frontend-kleinigheden — LAAG
- `templates/firewall.html:376` — lege `catch (e) {}` bij UFW-regels laden: fout = geen feedback, gebruiker denkt dat alles werkte.
- `templates/firewall.html:607` — whitelist-validatie ondersteunt geen IPv6/IPv6-CIDR (alleen `::1` hardcoded), terwijl de server wel IPv6 kan accepteren.
- `templates/notifications.html` — `escapeHtml()` is een duplicaat van `escHtml()` in `base.html`.
- `templates/base.html` (command palette, regel ~630) — `p.label` gaat onge-escaped in `innerHTML`. Labels zijn nu hardcoded dus geen echt risico, maar het patroon is fout en breekt zodra labels ooit dynamisch worden.

---

## 2. Security-verbeterpunten

De basis is goed; dit zijn aanscherpingen:

1. **CSP strakker** — `web/app.py:114-123` staat `cdn.jsdelivr.net` en Google Fonts nog toe, terwijl alles lokaal wordt geserveerd (en de README "No External CDN" claimt). Kan naar `'self'` (plus `'unsafe-inline'` zolang de inline scripts er zijn).
2. **`'unsafe-inline'` uitfaseren** — er staat ±8.000 regels inline JS in de templates. Verplaats gedeelde JS naar `static/app.js` (cachebaar, en maakt op termijn een CSP zonder `unsafe-inline` mogelijk via nonces).
3. **HSTS ontbreekt** — geen `Strict-Transport-Security` in `_set_security_headers()` (`app.py:126-131`). Eén regel; mag ook op de reverse proxy, maar dan gedocumenteerd.
4. **Sessie regenereren bij login** — `app.py:1380+` zet `session['logged_in']` zonder eerst `session.clear()`; standaard verdediging tegen session fixation.
5. **Rate limiting alleen op login** — de webhook (`/api/backup/webhook`, HMAC-beveiligd maar onbeperkt aanroepbaar) en API-endpoints die externe lookups doen (IP-geolocatie via SSH-logs) hebben geen limiet.
6. **2FA recovery codes ontbreken** — telefoon kwijt = lockout (alleen via SSH `config.json` bewerken te herstellen). Genereer 8-10 eenmalige backup codes bij het inschakelen van 2FA.

---

## 3. Performance-optimalisaties

1. **Seriële HTTP-checks per site** — `get_nginx_sites()` (`app.py:~1718`) draait per site een `curl` met timeout tot 10s, in serie. Bij 10 sites kan dat tientallen seconden duren. Parallelliseer met `concurrent.futures.ThreadPoolExecutor` (zoals al gedaan bij IP-geolocatie).
2. **Caches ruimen verlopen entries nooit op** — `_ttl_cache` (`app.py:312`) en `_ip_country_cache` (`app.py:~3941`) verwijderen verlopen entries alleen bij her-toegang tot dezelfde key. SSH-logs leveren een gestage stroom unieke IP's → langzame, onbegrensde groei. Voeg een periodieke sweep toe (kan in `_monitor_loop`).
3. **Productie-WSGI-server** — `app.py:7601` draait `app.run()` (Werkzeug dev-server). Voor één admin werkbaar, maar gunicorn/waitress geeft een degelijker worker-model, nettere timeouts en graceful reload. Met `waitress` is dit een 3-regel wijziging zonder extra OS-dependencies.

---

## 4. Ontbrekende zaken (gap-analyse)

Geverifieerd afwezig in de repo:

| # | Wat | Waarom het telt |
|---|-----|-----------------|
| 1 | **Backup van `data/`** (zie bug 1.1) | Secrets/2FA/VAPID onherstelbaar bij disk failure |
| 2 | **Tests** (0 testbestanden) | 7.600 regels kritieke code zonder vangnet; regressies zoals de 1.7.x notificatie-bugs waren met tests eerder gevangen |
| 3 | **CI** (geen `.github/workflows`) | Zelfs alleen `python -m py_compile` + `flake8` op elke push vangt breuk vóór de auto-update hem op de VPS zet |
| 4 | **Versie-pinning** in `requirements.txt` | Een verse install krijgt morgen andere versies dan vandaag; één breaking release van Flask/pywebpush breekt de tool |
| 5 | **`/health` endpoint** | De uptime-monitor bewaakt de websites, maar niets bewaakt de manager zelf; ook nuttig voor PM2/proxy checks |
| 6 | **Logrotatie** voor `/var/log/vps-backup.log` | Groeit onbegrensd; één logrotate-snippet lost het op |
| 7 | **2FA recovery codes** | Zie 2.6 |
| 8 | **Restore-flow** | Backups zijn te downloaden, maar herstel is volledig handwerk; minimaal een gedocumenteerde restore-procedure in de README |
| 9 | **Deployment-bestanden in de repo** | README zegt "run met PM2" maar er is geen `ecosystem.config.js` of systemd unit; nu is elke install handwerk |
| 10 | **API-rate limiting / Flask-Limiter** | Zie 2.5 |

Bewust géén aanbeveling: een database. Op deze schaal (max 100 notificaties, 1000 audit-entries, 288 metrics) zijn de atomic JSON-writes prima; SQLite zou complexiteit toevoegen zonder merkbaar voordeel.

---

## 5. Architectuur & onderhoudbaarheid

- **`app.py` is 7.601 regels** met ~80 routes, 246 functies, 0 classes, geen blueprints, geen type hints. Het werkt, maar elke wijziging raakt hetzelfde bestand en niets is in isolatie testbaar. Logische splitsing in Flask-blueprints: `auth`, `monitoring`, `webserver` (nginx/caddy), `files`, `firewall`, `notifications`, `system`. Dit kan incrementeel (één blueprint per release).
- **±8.100 regels inline JS** verspreid over templates, met duplicatie (`escHtml`/`escapeHtml`, toast/confirm-patronen, fetch-wrappers). Eén gedeelde `static/app.js` vermindert duplicatie én is een voorwaarde voor een strakkere CSP.
- **Hardcoded persoonlijke defaults in de scripts** — `nas-pull-backup.sh` (VPS-host/poort/webhook-URL) en `vps-backup.sh` (paden, backup-user) bevatten omgevingsspecifieke defaults; voor een publieke repo horen die in een gedocumenteerd `.backup_env`-bestand. *(Opgelost in v1.8.1: defaults zijn generiek gemaakt en gedocumenteerd in de README.)*
- **Cross-field configvalidatie ontbreekt** — `ssl_warning_days` < `ssl_critical_days` of onlogische DDoS-thresholds worden geaccepteerd (`app.py:~5630`, `config.py`).

---

## 6. Aanbevolen volgorde (top 10)

1. `data/`-directory van de manager opnemen in `vps-backup.sh` *(klein, voorkomt het grootste dataverlies-scenario)*
2. Versies pinnen in `requirements.txt`
3. `/health` endpoint + logrotate-snippet *(beide triviaal)*
4. `json_escape` in `nas-pull-backup.sh` repareren
5. TOTP-replay-bescherming + 2FA recovery codes
6. Corrupte config loggen i.p.v. stil negeren
7. HTTP-checks in `get_nginx_sites()` parallelliseren
8. CSP naar `'self'`, HSTS toevoegen, sessie regenereren bij login
9. CI-workflow met `py_compile`/`flake8` + eerste pytest-tests (begin bij pure functies: cron-validator, `is_path_allowed`, config-validatie)
10. Incrementeel naar blueprints + gedeelde `static/app.js`

Punten 1 t/m 4 zijn samen minder dan een dag werk en dekken de grootste praktische risico's af.
