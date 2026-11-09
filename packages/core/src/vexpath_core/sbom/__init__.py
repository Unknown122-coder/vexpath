"""SBOM handling: parse, validate, normalise and generate.

Every accepted input, whether a CycloneDX document, an SPDX document or one of
seven lockfile formats, becomes the same `Sbom` model. Nothing downstream
branches on where the inventory came from.
"""

from __future__ import annotations

from pathlib import Path

from vexpath_core.models.sbom import Sbom
from vexpath_core.protocols import Clock, SystemClock
from vexpath_core.sbom import cyclonedx, minimum_elements, spdx
from vexpath_core.sbom.cyclonedx import CycloneDxError
from vexpath_core.sbom.generate import generate_sbom, sbom_from_lockfile, serial_number
from vexpath_core.sbom.lockfiles import (
    LOCKFILE_PRIORITY,
    LockedPackage,
    LockfileError,
    LockfileResult,
    find_lockfiles,
    parse_lockfile,
)
from vexpath_core.sbom.spdx import SpdxError


class UnknownSbomFormatError(Exception):
    """Raised when a file is not a recognised SBOM document."""


def load(path: Path, *, clock: Clock | None = None) -> Sbom:
    """Read an SBOM document, detecting its format from the content.

    Detection reads the document rather than trusting the file extension,
    because SBOMs are routinely saved under names like ``sbom.json`` whatever
    their format.

    Raises:
        UnknownSbomFormatError: if the content matches no supported format.
        CycloneDxError, SpdxError: if the format is recognised but invalid.
    """
    resolved_clock = clock or SystemClock()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        msg = f"{path} could not be read as UTF-8 text: {exc}"
        raise UnknownSbomFormatError(msg) from exc

    probe = text.lstrip()[:4096]
    if '"bomFormat"' in probe and "CycloneDX" in probe:
        return cyclonedx.from_json(text, clock=resolved_clock)
    if '"spdxVersion"' in probe:
        return spdx.from_json(text, clock=resolved_clock)
    if probe.startswith("SPDXVersion:") or "\nSPDXVersion:" in text[:4096]:
        return spdx.from_tag_value(text, clock=resolved_clock)
    if probe.startswith("<?xml") or probe.startswith("<bom"):
        msg = (
            f"{path.name} looks like XML. CycloneDX XML is not read yet; convert it "
            "to JSON, or pass the JSON form."
        )
        raise UnknownSbomFormatError(msg)

    msg = (
        f"{path.name} is not a recognised SBOM. Supported: CycloneDX JSON "
        "(1.4 to 1.6) and SPDX (2.3 JSON or tag-value)."
    )
    raise UnknownSbomFormatError(msg)


def validate_document(path: Path) -> tuple[str, tuple[str, ...]]:
    """Validate a document and report its minimum-element gaps.

    Returns the detected format and the gaps. Schema validation failures raise;
    a gap is reported rather than raised, because an incomplete document is
    still analysable and the caller should decide what to do about it.
    """
    sbom = load(path)
    return sbom.format.value, minimum_elements.check(sbom)


def with_minimum_element_gaps(sbom: Sbom) -> Sbom:
    """Return the SBOM with its minimum-element gaps filled in."""
    return sbom.model_copy(update={"minimum_element_gaps": minimum_elements.check(sbom)})


__all__ = [
    "LOCKFILE_PRIORITY",
    "CycloneDxError",
    "LockedPackage",
    "LockfileError",
    "LockfileResult",
    "SpdxError",
    "UnknownSbomFormatError",
    "cyclonedx",
    "find_lockfiles",
    "generate_sbom",
    "load",
    "minimum_elements",
    "parse_lockfile",
    "sbom_from_lockfile",
    "serial_number",
    "spdx",
    "validate_document",
    "with_minimum_element_gaps",
]
