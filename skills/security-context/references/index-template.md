# Security context: {{project_name}}

Generated: {{date}}

## Purpose and scope

{{purpose}}

## Roles and permission matrix

| Role | Allowed actions | Explicitly denied actions | Evidence |
| --- | --- | --- | --- |
| {{role}} | {{allowed}} | {{denied}} | {{source}} |

## Trust boundaries and sensitive data

| Boundary or data | Source | Destination | Control / assumption |
| --- | --- | --- | --- |
| {{boundary}} | {{source}} | {{destination}} | {{control}} |

## Global controls

{{authentication_authorization_validation_and_logging_controls}}

## Module index

| Module | Covers | Entry points | Contract | Context confidence |
| --- | --- | --- | --- | --- |
| {{module}} (\`modules/{{module}}.md\`) | {{paths}} | {{entry_points}} | {{contract_summary}} | {{confidence}} |

## Assumptions and open questions

{{assumptions_and_questions}}
