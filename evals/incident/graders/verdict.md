---
type: llm
---
The final answer gives a per-project verdict for CVE-2021-23337 (lodash command injection, fixed in 4.17.21):
1. `shop-web` (lodash 4.17.20) is reported as affected.
2. It names 4.17.21 (or later) as the fixed version.
3. `docs-site` (lodash 4.17.21) is not reported as affected, and `billing-api` is not reported as using lodash.
4. If the OSV lookup failed or was unreachable, the answer says so and says where the affected range came from, instead of presenting the verdict as a tool-verified result.
5. It does not claim that a VEX statement or any other decision was recorded.
