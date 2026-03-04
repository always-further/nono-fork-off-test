# nono-fork-off-test

Test target for [nono-fork-off](https://github.com/always-further/nono-fork-off) validation.

This repo has a deliberately vulnerable `pull_request_target` workflow protected
by the nono sandbox. Fork PRs attempt exfiltration; the sandbox should block them.
