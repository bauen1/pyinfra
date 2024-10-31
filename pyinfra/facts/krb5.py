from __future__ import annotations

from typing import Any, Iterable, List, Optional, Tuple

from pyinfra.api import FactBase


class Krb5KeytabList(FactBase[Optional[List[Tuple[int, str]]]]):
    """
    List the keys contained in a keytab file

    Returns a list of tuples (kvno: int, principal: str) or None if the keytab
    file does not exist or is invalid

    .. code:: python

        [
            (1, "principal1"),
            (1, "principal2"),
            (2, "principal1"),
        ]
    """

    def requires_command(self, *args: Any, **kwargs: Any) -> str:
        return "klist"

    # Value to return if an error is encountered:
    @staticmethod
    def default() -> List[Any]:
        return []

    def command(self, keytab: str = "/etc/krb5.keytab") -> str:
        # FIXME: || true => run process to detect e.g. a missing file
        return f"klist -k {keytab} || true"

    def process(self, output: Iterable[str]) -> Optional[List[Tuple[int, str]]]:
        output = list(output)
        if len(output) < 3:
            return None

        if not output[0].startswith("Keytab name: FILE:"):
            return None
        elif not output[1].startswith("KVNO Principal"):
            return None
        elif not output[2].startswith("---- -"):
            return None

        keytab: List[Any] = []

        for line in output[3:]:
            (kvno, principal) = line.split()
            keytab.append((int(kvno), principal))

        return keytab
