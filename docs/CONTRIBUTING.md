# Contributing to veilnet

Thanks for your interest!

## Ground rules

1. **VM only for kernel code.** Never develop, load or test eBPF programs on your primary machine. Use a VM (see [docs/VM_SETUP.md](VM_SETUP.md)).
2. **Follow the plan.** Work is tracked in [PLAN_DETAILED.mmd](../PLAN_DETAILED.mmd). Keep changes minimal and justified.
3. **English only.** Code, comments, commit messages and docs are in English.

## Workflow

1. Fork, create a branch: `feature/your-thing` or `fix/your-thing`
2. Make your change
3. `cargo test` must pass; eBPF changes must compile with `just build-bpf` in a VM
4. Open a PR with a short description of what and why

## Commit style

`feat:`, `fix:`, `docs:`, `test:`, `chore:` prefixes.

## Code style

- Rust: standard `rustfmt` defaults
- C/eBPF: kernel style, 4 spaces, hard tab never; strict bounds checks for the verifier
- No secrets in code, ever
