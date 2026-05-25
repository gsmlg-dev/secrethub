# Issue tracker: GitHub

Issues and PRDs for this repo live as GitHub issues in `gsmlg-dev/secrethub`. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`, filtering comments by `jq` and also fetching labels.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

Infer the repo from `git remote -v` -- `gh` does this automatically when run inside a clone.

## Agent skills in requests

When creating a GitHub issue, PRD, implementation request, triage handoff, or any other request intended for an agent, include the relevant skills directly in the body. Do not rely on repository-level instructions alone.

Add this section near the top of the body:

```markdown
## Agent skills

- [$skill-name](/home/gao/.agents/skills/skill-name/SKILL.md) -- why this request should use it
- [$other-skill](/home/gao/.agents/skills/other-skill/SKILL.md) -- why this request should use it
```

Use the smallest set of skills that materially affects the work. For Elixir/Phoenix implementation requests, include the applicable Elixir, Phoenix, Ecto, OTP, TDD, review, or verification skills. For plan-to-issue conversion, include `to-issues`. For documentation-heavy handoffs, include the relevant documentation skill. If a request was produced from a conversation where the user explicitly invoked skills, carry those exact skill links into the issue or handoff body.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments`.
