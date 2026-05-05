# bash-guard test fixtures — third-party content

The 155 `*.json` files in this directory are imported verbatim from the
[balanced-safety-hooks](https://github.com/CodeAlive-AI/ai-driven-development/tree/main/hooks/balanced-safety-hooks)
project (path `hooks/balanced-safety-hooks/src/testdata/fixtures/`).

Each fixture encodes one Bash command, the cwd context, and the expected
decision (`allow` / `ask`) plus a granular `reason_code`. They are used by
`tests/fixture_runner.rs` to track baseline coverage of secguard's heuristic
and policy phases against an external corpus.

## Upstream license

```
MIT License

Copyright (c) 2026 CodeAlive-AI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Compatibility

secguard ships under `Apache-2.0 WITH Commons-Clause-1.0`. MIT-licensed test
fixtures may be redistributed inside this repository as long as the upstream
copyright and permission notice (above) are preserved. Modifications to the
fixtures should be marked.

If a fixture is altered locally, prefix the new file's name with `secguard_`
and document the diff inline in its description field.
