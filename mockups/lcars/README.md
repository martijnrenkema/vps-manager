# LCARS-thema — mockup

Een klikbare mockup om te beoordelen of een LCARS-skin voor VPS Manager de moeite waard is.
Open `index.html` in een browser; er is geen build- of serverstap nodig.

## Wat erin zit

Vijf schermen, bereikbaar via de rail links:

| Scherm | Waarom dit scherm |
| --- | --- |
| Dashboard | Statuskaarten, meters en grafieken — waar LCARS het sterkst is |
| Services | Een dichte tabel van twaalf rijen — de eerlijke stresstest |
| Beveiliging | Score, firewallregels en aanbevelingen door elkaar |
| Terminal | Monospace-uitvoer binnen een LCARS-frame |
| Mijn oordeel | De afweging: wat meezit, wat het kost, en een aanpak in vier stappen |

De overige negentien menu-items zijn aanwezig in de rail maar tonen een toelichting,
zodat zichtbaar is hoe een rail met 23 items zich gedraagt.

De getoonde serverwaarden komen uit een dashboardscreenshot; de meldingen en de
auditscore zijn illustratief gezet op een waarschuwingstoestand, zodat de
statuskleuren te beoordelen zijn.

## Bestanden

- `index.html` — de volledige mockup, zelfstandig, inclusief ingesloten lettertype
- `source.html` — hetzelfde bestand met `/*FONTS*/` als plaatshouder in plaats van de
  base64-fonts, zodat diffs leesbaar blijven
- `build-font.py` — genereert `fonts.css` uit Liberation Sans

## Het lettertype

LCARS leunt op ultra-condensed type (Swiss 911, Antonio). Geen van beide is hier
beschikbaar, en de Content Security Policy van een gepubliceerde pagina blokkeert
font-CDN's. `build-font.py` maakt daarom zelf een condensed variant: het subset
Liberation Sans tot de gebruikte tekens en schaalt de glyph-contouren horizontaal
(0.545 voor vet, 0.58 voor regulier). Het resultaat is twee woff2-bestanden van
samen ongeveer 15 kB, ingesloten als data-URI.

Voor productie is dit geen eindoplossing — kies daar een licentie of een open
alternatief zoals Antonio (SIL OFL).

```
pip install fonttools brotli
cd mockups/lcars && python3 build-font.py     # schrijft fonts.css
```

Vervang daarna `/*FONTS*/` in `source.html` door de inhoud van `fonts.css` om
`index.html` opnieuw op te bouwen.

## Bewust één thema

LCARS is een gecommitteerde visuele wereld op puur zwart; een lichte variant bestaat
niet. De tokens onder `:root[data-theme="light"]` zijn daarom gelijk aan de donkere,
zodat een themawissel deze pagina niet stukmaakt.
