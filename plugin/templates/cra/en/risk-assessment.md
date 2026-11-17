<!-- sbom-audit cra starter: delete this line once every blank is filled in -->
# Cybersecurity risk assessment: {{product}}

Regulation (EU) 2024/2847, Art. 13(2) and 13(3). Structure follows Annex I Part I. This document asks
questions; the answers are the manufacturer's. Nothing here is pre-filled, and a filled-in document is not a
statement that the product meets the Regulation. Evidence tooling, not legal advice.

- Product: {{product}} (repository `{{project}}`)
- Version(s) covered: ____
- Author(s): ____
- Last reviewed: ____-__-__
- Next review planned: ____-__-__
- Support period (Art. 13(8)), end date (month and year, Art. 13(19)): ____

Art. 13(3) asks the assessment to be documented and updated as appropriate during the support period, and
Art. 13(7) asks it to be updated where applicable when you become aware of vulnerabilities. Update
`Last reviewed` each time; `cra check` reports the document as stale after the configured review interval.

## 1. Intended purpose and reasonably foreseeable use (Art. 13(3))

- What is the product for, and who uses it? ____
- What uses, other than the intended one, can you reasonably foresee? ____
- Operational environment (where and how is it run, by whom, connected to what)? ____
- Assets to protect (data, functions, accounts, other systems)? ____
- How long is the product expected to be in use? ____

## 2. Threats and risks

| # | Threat or scenario | Asset affected | Likelihood | Impact | Existing measures | Remaining risk | Owner |
|---|---|---|---|---|---|---|---|
| 1 | ____ | ____ | ____ | ____ | ____ | ____ | ____ |

## 3. Annex I Part I (1): appropriate level of cybersecurity based on the risks

How do you apply point (1) in design, development and production? ____

## 4. Annex I Part I (2): applicability and implementation

For each point: does it apply to this product, and if so, how is it implemented? Where a point does not
apply, Art. 13(4) asks for a clear justification in the technical documentation.

| Point | Requirement (short) | Applies? (yes / no) | How it is implemented, or why it does not apply | Evidence (file, test, ticket) |
|---|---|---|---|---|
| (a) | No known exploitable vulnerabilities when made available | ____ | ____ | ____ |
| (b) | Secure by default configuration; reset to the original state | ____ | ____ | ____ |
| (c) | Vulnerabilities addressable through security updates (automatic by default where applicable, with opt-out) | ____ | ____ | ____ |
| (d) | Protection from unauthorised access; reporting possible unauthorised access | ____ | ____ | ____ |
| (e) | Confidentiality of stored, transmitted and processed data | ____ | ____ | ____ |
| (f) | Integrity of data, commands, programs and configuration; reporting corruption | ____ | ____ | ____ |
| (g) | Data minimisation | ____ | ____ | ____ |
| (h) | Availability of essential and basic functions, including after an incident | ____ | ____ | ____ |
| (i) | Minimise negative impact on the availability of other devices or networks | ____ | ____ | ____ |
| (j) | Limit attack surfaces, including external interfaces | ____ | ____ | ____ |
| (k) | Reduce the impact of an incident with exploitation mitigation | ____ | ____ | ____ |
| (l) | Record and monitor relevant internal activity, with an opt-out | ____ | ____ | ____ |
| (m) | Securely and easily remove all data and settings; secure data transfer | ____ | ____ | ____ |

## 5. Annex I Part II: how vulnerability handling is applied

| Point | Question | Your answer |
|---|---|---|
| (1) | Where is the SBOM, and which dependencies does it cover? (sbom-audit writes `sbom/{{project}}/<branch>.cdx.json`) | ____ |
| (2) | How are vulnerabilities addressed and remediated without delay? Are security updates separate from feature updates? | ____ |
| (3) | Which regular tests and reviews of security do you run, and how often? | ____ |
| (4) | Where do you publish information about fixed vulnerabilities? | ____ |
| (5) | Where is the coordinated vulnerability disclosure policy? (`cra/{{project}}/cvd-policy.md`) | ____ |
| (6) | Which contact address receives vulnerability reports? | ____ |
| (7) | How are updates distributed securely? | ____ |
| (8) | How are security updates disseminated without delay, and free of charge, with advisory messages? | ____ |

## 6. Open questions and decisions

- ____

## Review history

| Date | Reviewer | What changed |
|---|---|---|
| ____ | ____ | ____ |
