<!-- sbom-audit cra starter: delete this line once every blank is filled in -->
# Bewertung der Cybersicherheitsrisiken: {{product}}

Verordnung (EU) 2024/2847, Art. 13 Abs. 2 und 3. Der Aufbau folgt Anhang I Teil I. Dieses Dokument stellt
Fragen; die Antworten gibt der Hersteller. Nichts ist vorausgefüllt, und ein ausgefülltes Dokument ist keine
Aussage, dass das Produkt die Verordnung erfüllt. Nachweiswerkzeug, keine Rechtsberatung.

- Produkt: {{product}} (Repository `{{project}}`)
- Erfasste Version(en): ____
- Verfasst von: ____
- Zuletzt geprüft: ____-__-__
- Nächste Prüfung geplant: ____-__-__
- Unterstützungszeitraum (Art. 13 Abs. 8), Enddatum (Monat und Jahr, Art. 13 Abs. 19): ____

Nach Art. 13 Abs. 3 wird die Bewertung während des Unterstützungszeitraums dokumentiert und gegebenenfalls
aktualisiert, nach Art. 13 Abs. 7 gegebenenfalls auch, wenn Ihnen Schwachstellen bekannt werden. Tragen Sie bei
jeder Prüfung `Zuletzt geprüft` neu ein; `cra check` meldet das Dokument nach dem konfigurierten Intervall als
veraltet.

## 1. Zweckbestimmung und vernünftigerweise vorhersehbare Verwendung (Art. 13 Abs. 3)

- Wofür ist das Produkt da, und wer nutzt es? ____
- Welche Verwendung außer der vorgesehenen ist vernünftigerweise vorhersehbar? ____
- Betriebsumgebung (wo und wie läuft es, wer betreibt es, womit ist es verbunden)? ____
- Zu schützende Werte (Daten, Funktionen, Konten, andere Systeme)? ____
- Wie lange wird das Produkt voraussichtlich genutzt? ____

## 2. Bedrohungen und Risiken

| Nr. | Bedrohung oder Szenario | Betroffener Wert | Wahrscheinlichkeit | Auswirkung | Bestehende Maßnahmen | Restrisiko | Verantwortlich |
|---|---|---|---|---|---|---|---|
| 1 | ____ | ____ | ____ | ____ | ____ | ____ | ____ |

## 3. Anhang I Teil I Nummer 1: angemessenes Cybersicherheitsniveau angesichts der Risiken

Wie wenden Sie Nummer 1 in Konzeption, Entwicklung und Herstellung an? ____

## 4. Anhang I Teil I Nummer 2: Anwendbarkeit und Umsetzung

Für jeden Buchstaben: Ist er auf dieses Produkt anwendbar, und wenn ja, wie ist er umgesetzt? Ist er nicht
anwendbar, verlangt Art. 13 Abs. 4 eine klare Begründung in der technischen Dokumentation.

| Buchst. | Anforderung (kurz) | Anwendbar? (ja / nein) | Wie umgesetzt, oder warum nicht anwendbar | Nachweis (Datei, Test, Ticket) |
|---|---|---|---|---|
| a) | Ohne bekannte ausnutzbare Schwachstellen bereitgestellt | ____ | ____ | ____ |
| b) | Sichere Standardkonfiguration; Zurücksetzen in den ursprünglichen Zustand | ____ | ____ | ____ |
| c) | Schwachstellen durch Sicherheitsaktualisierungen behebbar (gegebenenfalls automatisch als Standard, mit Opt-out) | ____ | ____ | ____ |
| d) | Schutz vor unbefugtem Zugriff; Melden eines möglicherweise unbefugten Zugriffs | ____ | ____ | ____ |
| e) | Vertraulichkeit gespeicherter, übermittelter und verarbeiteter Daten | ____ | ____ | ____ |
| f) | Integrität von Daten, Befehlen, Programmen und Konfigurationen; Melden von Beschädigung | ____ | ____ | ____ |
| g) | Datenminimierung | ____ | ____ | ____ |
| h) | Verfügbarkeit wesentlicher und grundlegender Funktionen, auch nach einem Sicherheitsvorfall | ____ | ____ | ____ |
| i) | Negative Auswirkungen auf die Verfügbarkeit anderer Geräte oder Netze minimieren | ____ | ____ | ____ |
| j) | Möglichst geringe Angriffsflächen, auch bei externen Schnittstellen | ____ | ____ | ____ |
| k) | Auswirkungen eines Sicherheitsvorfalls durch Mechanismen zur Minderung der Ausnutzung verringern | ____ | ____ | ____ |
| l) | Aufzeichnung und/oder Überwachung einschlägiger interner Vorgänge, mit Opt-out | ____ | ____ | ____ |
| m) | Alle Daten und Einstellungen dauerhaft, sicher und einfach löschen; sichere Übertragung | ____ | ____ | ____ |

## 5. Anhang I Teil II: wie die Behandlung von Schwachstellen angewendet wird

| Nummer | Frage | Ihre Antwort |
|---|---|---|
| 1 | Wo liegt die Software-Stückliste, und welche Abhängigkeiten deckt sie ab? (sbom-audit schreibt `sbom/{{project}}/<branch>.cdx.json`) | ____ |
| 2 | Wie werden Schwachstellen unverzüglich behandelt und behoben? Kommen Sicherheitsaktualisierungen getrennt von Funktionsaktualisierungen? | ____ |
| 3 | Welche regelmäßigen Sicherheitstests und Überprüfungen gibt es, und wie oft? | ____ |
| 4 | Wo veröffentlichen Sie Informationen über beseitigte Schwachstellen? | ____ |
| 5 | Wo liegt die Strategie für die koordinierte Offenlegung von Schwachstellen? (`cra/{{project}}/cvd-policy.md`) | ____ |
| 6 | Welche Kontaktadresse nimmt Schwachstellenmeldungen an? | ____ |
| 7 | Wie werden Aktualisierungen sicher verbreitet? | ____ |
| 8 | Wie werden Sicherheitsaktualisierungen unverzüglich und kostenlos verbreitet, mit Hinweisen für die Nutzer? | ____ |

## 6. Offene Fragen und Entscheidungen

- ____

## Prüfhistorie

| Datum | Geprüft von | Was sich geändert hat |
|---|---|---|
| ____ | ____ | ____ |
