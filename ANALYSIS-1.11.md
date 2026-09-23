# Analyse VPS Manager (na v1.10.2)

Code-review van backend, frontend, scripts en performance, uitgevoerd met vier parallelle review-agents en daarna geverifieerd in de code. Deze branch bevat de fixes; onderaan staat wat bewust nog open is.

**Algemeen beeld:** de security-basis uit 1.8–1.10 staat nog steeds (CSP, CSRF, rate limiting, realpath-checks, atomic writes). De traagheid kwam bijna volledig van **synchrone shell-commando's in de request** (apt, certbot, fail2ban-client, du, volledige grep-scans van auth.log) met caches die korter leefden dan het monitor-interval. Een bezoek na een paar minuten trof daardoor bijna altijd een lege cache. Het "gedateerde" gevoel kwam van de standaard GitHub-darkpalet, uppercase-labels, veel inline styles en volledige page reloads na acties.

---

## 1. Performance ("voelt sloom")

Gemeten met de Flask test client: een koude `GET /` kostte **3,6–3,9 s**, bijna volledig `apt list --upgradable` plus `apt -s upgrade`. Na de wijzigingen laadt het dashboard met verlopen caches in **~0,2 s** en met warme caches direct.

| Wat | Was | Nu |
|---|---|---|
| `_ttl_cache` | Harde expiry, geen single-flight: elke verlopen key gaf een koude, trage request en gelijktijdige requests draaiden hetzelfde commando | **Stale-while-revalidate** plus single-flight. De oude waarde komt direct terug en wordt op de achtergrond ververst. De monitor-thread krijgt altijd verse data. |
| Dashboard | 6 collectors serieel | Parallel; caches worden bij het opstarten gevuld |
| apt / certbot / PHP-info | TTL van 2–5 min, dus bijna altijd koud | TTL van 10–30 min, stale tot 6–24 uur, ververst op de achtergrond |
| `/firewall` | 12+ subprocessen per load, zonder cache, serieel, plus een volledige grep van auth.log | Cache van 30 s, commando's parallel, auth.log via `tail` |
| `/firewall/banned-ips` (poll elke 30 s) | Elke poll: J+1× fail2ban-client, een kopie van de fail2ban-DB en geo-lookups | Cache van 30 s, alleen actieve bans, tijdelijke kopie altijd opgeruimd |
| `/ssh-logs` | 7 volledige scans van auth.log (kan honderden MB's zijn) | Eén pass in Python over de laatste 20 MB; IPv6 wordt ook geteld |
| `/disk` | Twee volledige `du`-scans, zonder cache | Eén scan, cache van 15 min |
| `/web-logs` | `awk \| sort` over complete access logs per site | Laatste 10k requests |
| `/uptime` | Per site tot 4× 5 s, serieel | Parallel |
| Services | Eén `systemctl show` per service | Eén aanroep, locale-onafhankelijk |
| Static files | Geen `max-age`: elke navigatie revalideerde ±6 bestanden | `?v=<hash>` en `Cache-Control: immutable` voor een jaar |
| Compressie | Geen (waitress comprimeert niet) | gzip voor HTML, JSON, CSS en JS |
| Chart.js | Van de jsDelivr-CDN, render-blocking | Lokaal meegeleverd, `defer` |
| Waitress | 8 threads | 16 threads; de self-update draait in een eigen thread |

## 2. Gerepareerde bugs

### Hoog
- **Knoppen deden niets.** `{{ x|tojson }}` stond in `onclick="..."` op het dashboard (restart van services en PM2), PHP en SSL. De dubbele quotes braken het attribuut af.
- **Fouten werden als succes getoond.** `apiCall()` gaf ook bij 4xx/5xx data terug, dus een mislukte restart zette de badge toch op "active".
- **Verlopen sessie of CSRF-token gaf "Connection error".** API-calls kregen een HTML-redirect, en CSRF-tokens verliepen na 1 uur. Nu krijgen ze 401-JSON, volgt er een redirect naar de login en leeft het token even lang als de sessie.
- **nginx-config kon niet opgeslagen worden.** De backup `<site>.backup` stond in `sites-enabled/` en werd bij `nginx -t` meegeladen (duplicate `default_server`/upstream). Een nieuw, ongeldig bestand bleef bovendien staan. Beide opgelost met een gedeelde write/validate/rollback-helper; backups staan nu in `data/config-backups/`. Bij Caddy speelde hetzelfde.
- **nginx-config groeide eindeloos.** Een logpad met "off" erin (coffee, office) werd gelezen als `access_log off`, waarna elke minuut een extra `access_log` werd ingevoegd en nginx werd herladen. Caddy-snippets met geneste blocks gaven dezelfde lus.
- **Self-update half toegepast bij het sluiten van de tab.** De update draaide in de SSE-generator. Hij draait nu in een eigen thread.

### Middel
- Verlopen push-subscriptions werden nooit verwijderd: `if e.response` is False bij 4xx. Het opruimen overschreef bovendien gelijktijdige (un)subscribes. `webpush` had ook geen timeout.
- Auto-heal startte services opnieuw die bewust gestopt waren (bijv. MariaDB voor onderhoud).
- De parser voor phased updates slokte de "will be upgraded"-lijst op, waardoor security-updates als "phased" verdwenen.
- SMTP-TLS controleerde het certificaat niet (MITM op het wachtwoord en op 2FA-codes).
- Sessies bleven geldig na een wachtwoord- of 2FA-wijziging. Dat is nu opgelost met een session epoch. Een half afgeronde 2FA-login verloopt na 10 min.
- Een DDoS-alert ging af op loopback-verbindingen (nginx naar PM2/PHP-FPM).
- Cron: de lijst werd 2 min gecachet zonder invalidatie, dus na toevoegen of bewerken wees de index naar de verkeerde job. Nu is er een gedeelde parser en een `expected`-controle (409). `@daily`/`@reboot` worden ondersteund, en een mislukte `crontab -l` wist niet meer de hele crontab.
- UFW-delete op regelnummer kon een verkeerde regel raken (bijv. de SSH-allow). Nu wordt eerst gecontroleerd of de regel nog klopt.
- De fail2ban-whitelist gebruikte `echo \| sudo tee` onder dash, wat backslashes in `jail.local` beschadigde. Bij een leesfout werd het hele bestand vervangen.
- nginx enable/disable kon een regular file in `sites-enabled` overschrijven of verwijderen.
- `/api/config` accepteerde elke key (`{"smtp": "x"}` liet de monitor crashen) en elke `backup_dir` (bijv. `/etc`, dat daarna via download leesbaar werd).
- Notificatie-dismiss werkte op positie en verwijderde daardoor de verkeerde notificatie. Dismiss gaat nu op een stabiel id.
- Swap leegmaken kon swap uitgeschakeld achterlaten (timeout bij `swapoff`, `swapon` werd niet uitgevoerd).
- Bij uploads werd een symlink als doel gevolgd.
- De terminal-allowlist was te omzeilen via een pad, bijv. `/var/www/x/ls`.
- De hele server-overview (en daarmee de disk/RAM-alerts) viel weg als één probe faalde, bijv. op ARM zonder "model name".
- "Update beschikbaar" verscheen ook bij een lokaal nieuwere versie (`!=` in plaats van een versievergelijking).
- Backup-script: `.env`-bestanden in de backup waren world-readable (644), en een falende `mysql` gaf toch "success".
- NAS-script: bij een langere VPS-storing konden alle snapshots, ook de nieuwste, gepruned worden.
- Update-watchdog: probede 127.0.0.1 ook als de app op een specifiek IP bindt, wat een valse rollback gaf.

### Laag
- Een ontbrekend binary (`php8.x`, `dig`) gaf een 500. Bij een timeout bleven pipeline-processen als wees doordraaien.
- Niet-string JSON-velden gaven een 500; negatieve `lines`-parameters ook.
- Secrets (`.secret_key`, VAPID-key) waren kort leesbaar met umask-rechten. De `.env`-lader hield quotes vast.
- De audit-clear wiste ook zijn eigen record.
- "Renew all" forceerde alle certificaten (Let's Encrypt rate limit).
- De alert-categorie werd uit de berichttekst gehaald: "PM2 process 'backup-worker'" werd als *backup* geclassificeerd.
- Diverse XSS-patronen in de frontend: `escHtml` binnen JS-strings in HTML-attributen, en onge-escapete `innerHTML`.

## 3. Frontend en look

Zie de commit "Modernise UI". In het kort:
- **Rustiger palet** buiten de standaard GitHub-kleuren.
- **Stijl:** hairline borders, sentence-case labels, tabular numbers, gevulde primaire knoppen, de sidebar-selectie als pill en een top bar met blur.
- **Gedeelde basis:** tokens voor radius, spacing en typografie, plus een `.skeleton`-utility.
- **Laden en navigatie:** een voortgangsbalk bij navigatie, view transitions, en polling die pauzeert in een verborgen tab.
- **Service worker:** cachet static assets echt en laat POST/API/SSE met rust.
- **Toegankelijkheid:** `:focus-visible`, `aria-label`s, `prefers-reduced-motion` en de iOS safe area.
- **Reboot:** zat verstopt achter de "Online"-statuschip en is nu een expliciete actie.

## 4. Nog open (aanbevelingen)

1. **`app.py` opsplitsen** (nu ~8.700 regels) in blueprints: auth, monitor/notify, collectors, webserver, files, firewall. Dit kan incrementeel, per release één blueprint.
2. **Tests.** Een eerste set pytest-tests voor de pure parsers: `_parse_crontab_lines`, `parse_ufw_rules`, `_find_default_ignoreip`, de nginx/Caddy-parsers, `validate_config` en `_version_tuple`. Voor de meeste bestaan in deze branch al fixture-achtige voorbeelden.
3. **Updater installeert `origin/main`** in plaats van de release-tag die de check toont. Resetten naar `v{latest}` is veiliger. Dit is niet aangepast omdat het de release-workflow raakt.
4. **Notificatie-spam bij live waarden.** RAM%, load en "disk full in ~N days" veranderen de berichttekst, waardoor na de cooldown opnieuw wordt gepusht. Dedupliceer op `key` zolang de alert actief is.
5. **Bootstrap afbouwen.** Er wordt 233 KB CSS en 81 KB JS geladen, vooral voor tooltips. Met CSS-only tooltips kan de JS weg.
6. **Inline JS naar `static/`.** Dat is een voorwaarde voor een CSP zonder `'unsafe-inline'`.
7. **Lange acties als achtergrondjob** met een statusendpoint: `apt upgrade`, certbot, directory-downloads (tar).
8. **2FA recovery codes** (sinds 1.8.0 open).
9. De Caddy-toggle weigert nu als de import-glob (`sites/*`) ook `.disabled`-bestanden laadt. Gebruik `import sites/*.caddy` of vergelijkbaar.
