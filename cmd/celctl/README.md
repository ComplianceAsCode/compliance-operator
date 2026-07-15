# celctl

CEL rule authoring and unit-test CLI for
[ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) rules
(`applications/<app>/<rule>/cel/shared.yml`). Expressions are evaluated through the
vendored compliance-sdk scanner — the same engine the operator's `cel-scanner` runs — so
results here match the Compliance Operator by construction.

## Install

```bash
go install github.com/ComplianceAsCode/compliance-operator/cmd/celctl@latest
# or from a checkout:
make celctl        # builds build/_output/bin/celctl
```

`celctl --help` lists the commands: `cac lint|scaffold|test|live` (the primary,
cac-content workflow), plus ad-hoc `eval`/`verify`/`live --expr` helpers and
kubectl-based `discover`/`samples`.

## Installing the Claude Code skill

The [`skill/`](skill/) directory contains a Claude Code skill (`cel-rule`) that teaches
Claude the authoring workflow (scaffold fixtures from real API objects, lint, unit-test,
live-evaluate). Install it by copying the directory into your Claude Code skills dir:

```bash
# from a compliance-operator checkout:
mkdir -p ~/.claude/skills
cp -r cmd/celctl/skill ~/.claude/skills/cel-rule
# or symlink it so the skill tracks your checkout:
ln -s "$PWD/cmd/celctl/skill" ~/.claude/skills/cel-rule
```

Restart Claude Code (or start a new session) to pick it up. To update, `git pull` (if
symlinked) or re-copy. You can also just ask Claude to do it: point it at this README and
say "install the cel-rule skill".
