# Example rulepack

Copy the example rulepack from [repo-sanitizer](https://github.com/Fermatix/repo-sanitizer):

```bash
git clone https://github.com/Fermatix/repo-sanitizer /tmp/repo-sanitizer
cp -a /tmp/repo-sanitizer/examples/rules/* skills/repo-pii-scrub/rules/
```

Then customize:

| File | Purpose |
|------|---------|
| `policies.yaml` | Which detectors run, severity thresholds |
| `extractors.yaml` | Tree-sitter zones (comments, string literals) |
| `dictionaries/*.txt` | Client names, product codenames, internal terms |

Re-run `repo-sanitizer scan` after dictionary updates.
