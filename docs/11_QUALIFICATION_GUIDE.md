# 11 — Qualification Guide (each member does this individually)

Every participant must complete qualification and be selected before competing. Completing it doesn't guarantee selection, so do it carefully.

## Steps
1. **Register individually** through the official form.
2. **Find the official AeglysAI repository.** The link should be on the official form, event page or confirmation email. If you can't find it, email aegython@aeglysai.com. Don't guess or use an unofficial copy.
3. **Fork** it to your own GitHub account (Fork button, top right).
4. **Clone and run the baseline:**
   ```bash
   git clone https://github.com/<your-username>/<repo>.git
   cd <repo>
   # follow the repo's README: install dependencies, build, run
   ```
5. **Capture sanitised build evidence:** a screenshot or terminal log showing a successful build or run. Before sharing, remove usernames in paths, tokens, emails and IPs you don't want public.
6. **Write the qualification notes** (template below) as `QUALIFICATION.md` in your fork. Commit and push.
7. **Submit** your fork link, the notes link and the evidence through the official channel.

## Template: `QUALIFICATION.md`
```markdown
# AeglysAI Qualification — <Your Name>

## Environment
OS, language/runtime versions, how long the build took.

## Build / run evidence
Commands used, result, screenshot link (sanitised).

## Architecture overview
- Main components/modules and what each does (3–8 bullets)
- Simple diagram (ASCII or image)

## Request / decision flow
Step-by-step: what happens from input to decision/output.
1. ...
2. ...

## One meaningful technical observation
Something specific you noticed in the code: a design choice, a bug, a missing check,
a performance issue, unclear error handling. Point to the file and line.

## One realistic improvement idea
What you would change, why it helps, and roughly how.

## Proposed validation approach
How you would prove the improvement works: test cases, metric, before/after comparison.
```

## Tips that help selection
- Be **specific**. Name files, functions and line numbers. Generic notes look copied.
- Choose an observation linked to security or reliability, such as input validation, error handling, logging or tests. That matches the hackathon's theme.
- Keep the improvement **small and realistic**, something you could build in a day.
- Make the validation **measurable**, for example "add 5 unit tests; error rate on malformed input drops from X to 0".
- Each member writes their **own** notes. Copied notes may be rejected.

## Using Claude for this
Prompt for the coding Claude, after cloning:
> Read this repository. Explain its architecture and request/decision flow in simple terms with file references. Suggest 3 candidate technical observations and 3 small improvement ideas with validation approaches. Don't write my final notes; I will choose and write them myself.

Use Claude to *understand* the code, then write the notes in your own words, because you will be asked about them.
