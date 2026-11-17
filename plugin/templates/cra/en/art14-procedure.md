<!-- sbom-audit cra starter: delete this line once every blank is filled in -->
# Reporting procedure (Art. 14): {{product}}

Regulation (EU) 2024/2847, Art. 14. Art. 14 applies from 11 September 2026 (Art. 71(2)), also to products
placed on the market before 11 December 2027 (Art. 69(3)). Evidence tooling, not legal advice: decide with your
own counsel whether a case is reportable.

- Last reviewed: ____-__-__

## What has to be reported

- **Actively exploited vulnerability** in the product (Art. 14(1)): "a vulnerability for which there is
  reliable evidence that a malicious actor has exploited it in a system without permission of the system
  owner" (Art. 3(42)).
- **Severe incident having an impact on the security of the product** (Art. 14(3)). Severe means (Art. 14(5)):
  it negatively affects, or can affect, the product's ability to protect the availability, authenticity,
  integrity or confidentiality of sensitive or important data or functions; or it has led, or can lead, to the
  introduction or execution of malicious code in the product or in a user's network and information systems.

A CISA KEV entry in `AUDIT.md` says a vulnerability is exploited somewhere. It does not by itself say that it is
exploited in your product; that judgement is yours. Treat a KEV finding in a product as the moment to run this
procedure and decide.

## Where

Via the single reporting platform run by ENISA (Art. 16), to the electronic notification end-point of the
CSIRT designated as coordinator of the Member State of your main establishment in the Union (Art. 14(7));
ENISA receives the notification at the same time.

- Our main establishment (Member State): ____
- Coordinator CSIRT: ____
- Platform account holder(s): ____
- Platform: https://portal.cra-srp.enisa.europa.eu/ (check the address against ENISA's own site before use)

## Deadlines

| Step | Actively exploited vulnerability (Art. 14(2)) | Severe incident (Art. 14(4)) | Draft |
|---|---|---|---|
| Early warning | within 24 hours of becoming aware; Member States where the product is made available, where applicable | within 24 hours of becoming aware; at least whether unlawful or malicious acts are suspected; Member States, where applicable | `art14/early-warning.md` |
| Notification | within 72 hours of becoming aware, unless already provided | within 72 hours of becoming aware, unless already provided | `art14/notification.md` |
| Final report | no later than 14 days after a corrective or mitigating measure is available | within one month after the incident notification | `art14/final.md` |

The coordinator CSIRT may ask for an intermediate report (Art. 14(6)).

## Informing users (Art. 14(8))

After becoming aware, inform the impacted users (and where appropriate all users) of the vulnerability or
incident and, where necessary, of mitigation and corrective measures they can deploy, where appropriate in a
structured, machine-readable format.

- Channel(s) to reach users: ____
- Machine-readable format used (for example a CSAF advisory): ____

## Who does what

| Role | Name | Deputy | How to reach them outside office hours |
|---|---|---|---|
| Decides whether a case is reportable | ____ | ____ | ____ |
| Submits to the platform | ____ | ____ | ____ |
| Informs users | ____ | ____ | ____ |

## Record of cases

Keep a line per case here (or in `log.md`), with the time you became aware: the deadlines run from it.

| Became aware (date, time, zone) | Case | Reportable? Why | Early warning sent | Notification sent | Final report sent |
|---|---|---|---|---|---|
| ____ | ____ | ____ | ____ | ____ | ____ |
