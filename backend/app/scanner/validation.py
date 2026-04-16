"""Validation helpers for scanner inputs."""
import shlex

# Flags that could be used to read/write files, pivot to unintended hosts,
# or inject arbitrary arguments into nmap. nmap is invoked via subprocess list
# form (no shell), so shell metacharacters are not a direct injection vector —
# the risk here is nmap-level feature abuse.
_BLOCKED_NMAP_FLAGS: frozenset[str] = frozenset({
    # Write output to arbitrary paths
    "-oN", "-oX", "-oG", "-oA", "-oS",
    # Read target list from a file (pivot to unintended hosts)
    "-iL", "--inputfilename",
    # Script argument injection
    "--script-args", "--script-args-file",
    # Override nmap data/service/version databases
    "--datadir", "--servicedb", "--versiondb",
    # Idle/zombie scan — uses a third-party host for spoofed packets
    "-sI", "--idlescan",
    # Route scans through proxies
    "--proxies",
})

# Prefix-based checks for flags that embed a value without a separator,
# e.g. -oN/tmp/out or --script-args=foo
_BLOCKED_NMAP_PREFIXES: tuple[str, ...] = (
    "-oN", "-oX", "-oG", "-oA", "-oS",
    "-iL",
    "--script-args",
    "--datadir",
    "--servicedb",
    "--versiondb",
    "--inputfilename",
    "--idlescan",
    "--proxies",
)


def validate_nmap_args(args: str) -> None:
    """
    Raise ``ValueError`` if *args* contains nmap flags that could be used to:

    - Read or write files on the scanner host (-iL, -oN, -oX, …)
    - Inject arbitrary script arguments (--script-args)
    - Override nmap internal data directories (--datadir, --servicedb, …)
    - Pivot to unintended hosts via idle scan (-sI)
    - Route packets through proxies (--proxies)

    Safe flags such as ``-sV``, ``-O``, ``-T4``, ``-p``, ``--top-ports``,
    ``--host-timeout``, ``--min-rate``, and ``--script`` (without args) are
    all permitted.
    """
    try:
        tokens = shlex.split(args)
    except ValueError as exc:
        raise ValueError(f"Malformed nmap argument string: {exc}") from exc

    for token in tokens:
        # Normalise --flag=value → --flag
        flag = token.split("=")[0]

        if flag in _BLOCKED_NMAP_FLAGS:
            raise ValueError(
                f"Nmap flag '{flag}' is not permitted in custom scan arguments. "
                "Remove output-file, input-file, script-args, and proxy flags."
            )

        # Catch adjacent-value forms like -oNoutfile or --script-args:foo
        for prefix in _BLOCKED_NMAP_PREFIXES:
            if flag != prefix and flag.startswith(prefix):
                raise ValueError(
                    f"Nmap flag matching '{prefix}*' is not permitted in custom scan arguments."
                )
