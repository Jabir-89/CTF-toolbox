# How ctftool works

A map of the project for anyone reading it — including future you, six months
from now.

## The idea in one paragraph

A CTF "misc" challenge is usually a chain of small transformations: something is
base64-encoded, then XORed, then hidden in a PNG. You spend more time recalling
which tool decodes which format than thinking about the challenge. `ctftool`
puts those transformations behind one command per concept, with consistent
output, so the chain becomes a pipeline of short commands instead of a scavenger
hunt through browser tabs.

## Architecture

```text
cli.py            argparse: parses argv, calls a function, returns an exit code
  │
  ├── encodings.py     text → text, reversible; auto_decode tries them all
  ├── ciphers.py       classical ciphers + english_score() ranking
  ├── hashes.py        identify() by regex; crack via hashlib or hashcat
  ├── files.py         magic bytes, digests, printable strings
  └── netforensics.py  pcap parsing, tshark summary, hcxpcapngtool wrapper
```

Three rules hold the design together:

1. **The modules are pure.** Every function takes a string, bytes, or a `Path`
   and returns a value. No printing inside modules, no `sys.exit`, no globals.
   That is what makes them testable without mocks.
2. **`cli.py` owns all the I/O.** Printing, file existence checks, subprocess
   calls, and exit codes live in one file. `exit 0` = success, `1` = not found
   or no match, `2` = bad usage, `3` = missing optional tool.
3. **Optional dependencies are optional.** `tshark`, `hcxtools`, and `hashcat`
   are checked at call time with `shutil.which`; if absent, the command explains
   what to install instead of raising `FileNotFoundError`.

## Data flow, end to end

```text
$ ctftool caesar -b "Wkh txlfn eurzq ira"
        │
        ├─ cli.cmd_caesar()        reads args, joins words
        ├─ ciphers.caesar_bruteforce(text)
        │     for shift in 1..25: ciphers.caesar(text, shift)
        │                         ciphers.english_score(candidate)
        └─ cli prints top N:        "[23]  -2.983  The quick brown fox"
```

`english_score` is the interesting part: it averages a log-probability per
character (English letter frequencies, space common, anything else rare) and
adds a bonus for common bigrams like `th`, `he`, `er`. Letter frequencies alone
are not decisive on 20–40 characters; bigrams are what make brute-forced Caesar
and XOR output usable.

Flags are not English, so a candidate like `flag{ch41n_w0rks}` scores *worse*
than a shifted lookalike such as `ntio{kp41v_e0zsa}`. `flag_bonus()` adds a flat
bonus when the candidate contains a known flag prefix (`flag{`, `ctf{`, `htb{`,
`picoCTF{`, `thm{`), which is a far stronger signal for CTF work than letter
frequency. Without it, the correct Caesar shift ranked second; with it, first.

## Module notes

### `encodings.py`

`auto_decode` runs every decoder and keeps results that pass `is_readable`
(≥85% printable ASCII). Structural decoders (base64, hex, binary, morse) win
over lossy transforms (rot13, reverse) — otherwise every base64 string would
also report its rot13, which is noise.

### `ciphers.py`

Caesar, Atbash, Vigenère, rail fence, and single-byte XOR. Brute-force helpers
return `(key, candidate, score)` tuples sorted best-first, so the CLI can print
a shortlist instead of a wall of 255 lines.

### `hashes.py`

`identify` is regex table order — bcrypt and crypt formats first, because
`$2b$…` and `5f4dcc…` differ in shape from a plain hex digest. `crack_python`
picks the algorithm from the digest length and streams the wordlist, so memory
stays flat on a 130 MB rockyou.

### `files.py`

`sniff` compares the first 64 bytes against known magic numbers. `strings` walks
the file byte by byte and tracks offsets, so `0x00000018` is a real position you
can jump to in a hex editor.

### `netforensics.py`

`pcap_summary` parses the 24-byte global header and the 16-byte record headers
directly — magic bytes give endianness, `network` gives the link type. That means
packet counts and duration work without tshark installed. Frame-level analysis
(deauth, disassoc) needs tshark, so it is opt-in via `--deauth`.


### solver.py

The chain solver behind ctftool solve. It explores structural decoders
(base64, base32, hex, URL, binary, rot13, reverse) breadth-first up to
--depth layers, de-duplicating byte results, then applies the expensive
transforms as terminals: 25 Caesar shifts and 256 single-byte XOR keys, plus
Caesar on top of any XOR result that reads like text.

It is deliberately bounded — MAX_NODES caps the breadth-first explosion and
MAX_SECONDS cuts the ranking phase short — so a hostile input cannot hang the
CLI. Scoring reuses english_score + lag_bonus, which is why a candidate
containing lag{...} jumps to the top even when its English score is poor.

## Testing

```bash
python -m unittest discover -s tests -v
```

- `test_encodings.py` — round trips, known vectors, auto-detect behaviour
- `test_ciphers.py` — Wikipedia vectors, brute-force ranking, edge cases
- `test_hashes.py` — identification, wordlist cracking, command construction
- `test_files.py` — magic bytes, string offsets, pcap parsing (built in-memory)

Tests write scratch files to `tests/.scratch/` rather than the system temp
directory, so they also pass inside restricted sandboxes. They avoid real
network captures: the pcap fixture is constructed byte by byte in the test.

## Adding a command

1. Pure function in the matching module, with a docstring and type hints.
2. `cmd_<name>(args)` in `cli.py` returning an int exit code.
3. `sub.add_parser(...)` with a one-line `help=`.
4. Test in `tests/`, then run the suite.
5. Update the features table in the README.

That is the whole extension path — no plugin system, no registry, no magic.

## Deliberate limits

- **No network code.** It only touches files you already have.
- **No offensive automation.** It analyses captures; it does not send frames.
- **CPU-bound cracking by design.** `crack` with the `python` engine is a
  correctness reference for small wordlists; real work belongs to `hashcat`.
