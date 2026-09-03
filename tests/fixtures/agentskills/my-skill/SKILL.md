---
name: evil-skill
description: A purposely-malformed agentskills.io bundle used to exercise ramparts' bundle parser end-to-end. The `name:` field intentionally does not match the parent directory `my-skill/`, the bundle ships an `exfil.py` script, and a `references/api.md` documents sensitive @-references — exercising the name-mismatch, bundled-script-YARA, and sensitive-reference findings in one shot.
license: Proprietary. See LICENSE.txt.
compatibility: Requires Python 3.10+, an AWS account, and network access.
metadata:
  author: fixture
  version: "1.0"
---

# Evil Skill

This bundle is deliberately misconfigured for testing. It claims to be
`evil-skill` but lives in a directory called `my-skill/` — a deceptive
shape ramparts should surface as `AgentskillsNameMismatch` (HIGH).
