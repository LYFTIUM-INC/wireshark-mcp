## Summary
- Implement full Wireshark MCP tool suite (core + advanced)
- Restructure repo; remove "enhanced" from filenames; add CLI
- Add robust tests with mocked subprocess; CI and linting configs
- Harden security (no shell interpolation; sg fallback gated)

## Changes
- server.py: all tools, hardened capture, protocol stats, enhanced PCAP analysis
- wireshark_mcp/: package + CLI (`wireshark-mcp-server`)
- tests/: unit tests with async subprocess mocks
- Configs: pyproject, ruff, pytest, pre-commit, editorconfig, CI
- Docs: updated README, tool report, capture notes

## Verification
- Tests: `pytest -q` (all green)
- Lint: `ruff check .`, `black --check .`
- CLI: `wireshark-mcp-server` starts server

## Security
- Subprocess calls use argv lists; no shell injection
- sg fallback disabled by default (`WIRESHARK_ENABLE_SG=1` to enable)

## Checklist
- [ ] Updated README and docs
- [ ] CI green
- [ ] All tools registered and callable