# Contributing

Thanks for looking. This is a small project, so the rules are short.

## Setup

```bash
git clone https://github.com/Jabir-89/CTF-toolbox.git
cd ctf-toolbox
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Ground rules

1. **Stdlib first.** Core commands must run on a clean Python 3.9 without
   `pip install` of anything. Optional tools (`tshark`, `hcxtools`, `hashcat`)
   must degrade gracefully — check for them and print a clear message.
2. **Every new function gets a test.** Put it in `tests/`, use `unittest`.
3. **No network code.** No sockets, no requests, no telemetry. This tool works
   on files the user already has.
4. **No offensive automation.** Features that transmit frames, attack live
   networks, or target third-party systems are out of scope by design.
5. **Output format.** One result per line, `[name] value` style, so results
   compose with `grep` and `xargs`.

## Adding a subcommand

1. Write the pure function in the relevant module (`encodings.py`, `ciphers.py`, …).
2. Add `cmd_<name>` in `cli.py`.
3. Register it in `build_parser()` with a one-line `help=`.
4. Add tests, then update the README features table.
5. Run `python -m unittest discover -s tests -v` and the CLI manually once.

## Commit style

Short imperative subject, e.g. `add rail fence decode`, `fix hex padding`.
One logical change per commit.

## Reporting bugs

Open an issue with: what you ran, what you expected, what happened, and your
Python version (`python --version`). If a capture or file is involved, do not
attach data you are not allowed to share — describe the structure instead.
