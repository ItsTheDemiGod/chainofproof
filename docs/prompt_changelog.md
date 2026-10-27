# Prompt and agent-parameter changelog

Rule A2: prompts and agent parameters are FIXED before the first real run. They are never iterated to
improve key-based scores (the `agent-peek` numbers exist only to check that the mechanics work). Every
change to a prompt template, an output schema, the tool listing or an `agent` setting after the first
real run needs an entry here: date, what, why, and which observed problem triggered it.

`prompt_version` is the sha256 of all templates, both output schemas and the tool listings
(`agents/prompts.py: prompt_version()`); it is stored in every `agent_runs` row and in the ledger
`run_start` entry.

| date | prompt_version | what | why / observed problem |
|---|---|---|---|
| 2026-10-27 | `0dc201dec9fff2cba4daadff7494184bcbc694c13c8c2e730684bf9b33f81f3f` | v1 initial | First version, written before any real run. Agent settings as in `config/settings.yaml` section `agent` (rationale: `docs/agents.md`). |
