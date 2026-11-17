# Inventory

Generated 2026-11-07T02:58:00Z from `.` (portfolio mode, branches `main`, `dev`). Components come from the Syft SBOM of each branch's committed tree (`sbom/<project>/<branch>.cdx.json`) plus own readers for images and runtime pins; the working tree is never read. Findings: `AUDIT.md`; full data: `inventory.json`.

## Overview

| Project | Branch | Node | Python | Deno | Expo/React Native | SvelteKit | NestJS | Astro | Vite | FastAPI | Postgres | Images |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| billing-api | main | – | – | – | – | – | – | – | – | – | – | `python:3.12-slim` |
| docs-site | main | – | – | – | – | – | – | – | – | – | – | – |
| shop-web | main | 18 | – | – | – | – | – | – | – | – | – | `node:18-alpine` |

## billing-api

- **`main`** 0000000 (in sync with origin): 1 packages (PyPI 1; 1 direct, 0 dev-only), 1 images, 0 runtime pins

**Runtimes & images**

| Product / image | Cycle / tag | Kind | Detail | Source | Branches |
|---|---|---|---|---|---|
| `python:3.12-slim` | 3.12-slim | image | pinned to minor | `Dockerfile` | `main` |

**Direct dependencies** (1; `⚠︎` = version differs between branches)

| Package | Ecosystem | Manifest | `main` | Scope |
|---|---|---|---|---|
| requests | PyPI | `requirements.txt` | 2.31.0 | required |

## docs-site

- **`main`** 0000000 (in sync with origin): 1 packages (npm 1; 1 direct, 0 dev-only), 0 images, 0 runtime pins

**Direct dependencies** (1; `⚠︎` = version differs between branches)

| Package | Ecosystem | Manifest | `main` | Scope |
|---|---|---|---|---|
| lodash | npm | `package-lock.json` | 4.17.21 | required |

## shop-web

- **`main`** 0000000 (in sync with origin): 1 packages (npm 1; 1 direct, 0 dev-only), 1 images, 1 runtime pins

**Runtimes & images**

| Product / image | Cycle / tag | Kind | Detail | Source | Branches |
|---|---|---|---|---|---|
| `node:18-alpine` | 18-alpine | image | pinned to major | `Dockerfile` | `main` |
| `nodejs` | 18 | runtime | engines.node >=18 | `package.json` | `main` |

**Direct dependencies** (1; `⚠︎` = version differs between branches)

| Package | Ecosystem | Manifest | `main` | Scope |
|---|---|---|---|---|
| lodash | npm | `package-lock.json` | 4.17.20 | required |

