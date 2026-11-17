<!-- sbom-audit cra starter: delete this line once every blank is filled in -->
# Meldeverfahren (Art. 14): {{product}}

Verordnung (EU) 2024/2847, Art. 14. Art. 14 gilt ab dem 11. September 2026 (Art. 71 Abs. 2), auch für
Produkte, die vor dem 11. Dezember 2027 in Verkehr gebracht wurden (Art. 69 Abs. 3). Nachweiswerkzeug, keine
Rechtsberatung: Ob ein Fall meldepflichtig ist, entscheiden Sie mit Ihrer eigenen Rechtsberatung.

- Zuletzt geprüft: ____-__-__

## Was gemeldet werden muss

- **Aktiv ausgenutzte Schwachstelle** im Produkt (Art. 14 Abs. 1): eine Schwachstelle, für die es zuverlässige
  Belege gibt, dass ein böswilliger Akteur sie in einem System ohne Erlaubnis des Systemeigentümers ausgenutzt
  hat (Art. 3 Nr. 42).
- **Schwerwiegender Sicherheitsvorfall mit Auswirkungen auf die Sicherheit des Produkts** (Art. 14 Abs. 3).
  Schwerwiegend ist er nach Art. 14 Abs. 5, wenn er die Fähigkeit des Produkts beeinträchtigt oder
  beeinträchtigen kann, die Verfügbarkeit, Authentizität, Integrität oder Vertraulichkeit sensibler oder
  wichtiger Daten oder Funktionen zu schützen, oder wenn er zur Einschleusung oder Ausführung von Schadcode im
  Produkt oder in den Netz- und Informationssystemen eines Nutzers geführt hat oder führen kann.

Ein Eintrag im CISA-KEV-Katalog in `AUDIT.md` sagt, dass eine Schwachstelle irgendwo ausgenutzt wird. Er sagt
nicht von selbst, dass sie in Ihrem Produkt ausgenutzt wird; das beurteilen Sie. Ein KEV-Befund in einem Produkt
ist der Anlass, dieses Verfahren durchzugehen und zu entscheiden.

## Wohin

Über die einheitliche Meldeplattform der ENISA (Art. 16) an den elektronischen Meldeendpunkt des als
Koordinator benannten CSIRT des Mitgliedstaats Ihrer Hauptniederlassung in der Union (Art. 14 Abs. 7); die
ENISA erhält die Meldung gleichzeitig.

- Unsere Hauptniederlassung (Mitgliedstaat): ____
- Koordinierendes CSIRT: ____
- Zugang zur Plattform hat/haben: ____
- Plattform: https://portal.cra-srp.enisa.europa.eu/ (Adresse vor der Nutzung auf der Website der ENISA prüfen)

## Fristen

| Schritt | Aktiv ausgenutzte Schwachstelle (Art. 14 Abs. 2) | Schwerwiegender Sicherheitsvorfall (Art. 14 Abs. 4) | Entwurf |
|---|---|---|---|
| Frühwarnung | innerhalb von 24 Stunden nach Kenntnis; gegebenenfalls die Mitgliedstaaten, in denen das Produkt bereitgestellt wurde | innerhalb von 24 Stunden nach Kenntnis; mindestens, ob rechtswidrige oder böswillige Handlungen vermutet werden; gegebenenfalls die Mitgliedstaaten | `art14/early-warning.md` |
| Meldung | innerhalb von 72 Stunden nach Kenntnis, sofern nicht bereits übermittelt | innerhalb von 72 Stunden nach Kenntnis, sofern nicht bereits übermittelt | `art14/notification.md` |
| Abschlussbericht | spätestens 14 Tage, nachdem eine Korrektur- oder Abhilfemaßnahme verfügbar ist | innerhalb eines Monats nach der Meldung des Sicherheitsvorfalls | `art14/final.md` |

Das koordinierende CSIRT kann einen Zwischenbericht anfordern (Art. 14 Abs. 6).

## Nutzer informieren (Art. 14 Abs. 8)

Nach Kenntnis informieren Sie die betroffenen Nutzer (und gegebenenfalls alle Nutzer) über die Schwachstelle
oder den Vorfall und, falls erforderlich, über Maßnahmen zur Risikominderung und Korrektur, die sie ergreifen
können, gegebenenfalls in einem strukturierten, maschinenlesbaren Format.

- Kanal/Kanäle zu den Nutzern: ____
- Verwendetes maschinenlesbares Format (zum Beispiel ein CSAF-Advisory): ____

## Wer macht was

| Rolle | Name | Vertretung | Erreichbarkeit außerhalb der Arbeitszeit |
|---|---|---|---|
| Entscheidet, ob ein Fall meldepflichtig ist | ____ | ____ | ____ |
| Übermittelt an die Plattform | ____ | ____ | ____ |
| Informiert die Nutzer | ____ | ____ | ____ |

## Fallprotokoll

Eine Zeile je Fall hier (oder in `log.md`), mit dem Zeitpunkt der Kenntnis: Ab ihm laufen die Fristen.

| Kenntnis (Datum, Uhrzeit, Zeitzone) | Fall | Meldepflichtig? Warum | Frühwarnung gesendet | Meldung gesendet | Abschlussbericht gesendet |
|---|---|---|---|---|---|
| ____ | ____ | ____ | ____ | ____ | ____ |
