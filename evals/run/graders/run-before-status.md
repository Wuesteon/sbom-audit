---
type: tool_order
before: {tool: Bash, input_match: 'sbom_audit_cli\.py\\?"? run\b(?![^"]*--help)'}
after: {tool: Bash, input_match: 'sbom_audit_cli\.py\\?"? status'}
---
