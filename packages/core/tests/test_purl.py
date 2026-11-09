"""Package URL handling.

These tests matter more than their size suggests. A purl is the join key
between an SBOM component and an advisory's affected package, so a
normalisation mistake does not raise an error, it silently loses findings.
"""

from __future__ import annotations

import pytest

from sscp_core.purl import build_purl, normalise_name, parse_purl


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("Flask-SQLAlchemy", "flask-sqlalchemy"),
        ("flask_sqlalchemy", "flask-sqlalchemy"),
        ("Flask.SQLAlchemy", "flask-sqlalchemy"),
        ("flask--sqlalchemy", "flask-sqlalchemy"),
        ("zope.interface", "zope-interface"),
        ("  requests  ", "requests"),
    ],
)
def test_pypi_names_normalise_per_pep_503(given: str, expected: str) -> None:
    assert normalise_name("PyPI", given) == expected


def test_every_pypi_spelling_produces_one_purl() -> None:
    spellings = ["Flask-SQLAlchemy", "flask_sqlalchemy", "FLASK.SQLALCHEMY"]
    purls = {build_purl("PyPI", name, "3.1.1") for name in spellings}
    assert purls == {"pkg:pypi/flask-sqlalchemy@3.1.1"}


def test_go_module_paths_keep_their_case() -> None:
    # Go module paths are case-sensitive; lowercasing them would break matching.
    assert normalise_name("Go", "github.com/Masterminds/semver") == (
        "github.com/Masterminds/semver"
    )


def test_maven_coordinates_keep_their_shape() -> None:
    assert normalise_name("Maven", "com.fasterxml.jackson.core:jackson-databind") == (
        "com.fasterxml.jackson.core:jackson-databind"
    )


@pytest.mark.parametrize(
    ("ecosystem", "name", "version", "expected"),
    [
        ("PyPI", "requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
        ("npm", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20"),
        ("crates.io", "serde", "1.0.0", "pkg:cargo/serde@1.0.0"),
        ("RubyGems", "rails", "7.1.0", "pkg:gem/rails@7.1.0"),
        ("Packagist", "symfony/console", "6.4.0", "pkg:composer/symfony/console@6.4.0"),
    ],
)
def test_ecosystem_names_map_to_purl_types(
    ecosystem: str, name: str, version: str, expected: str
) -> None:
    # OSV and purl disagree on several spellings, which is why the mapping is
    # an explicit table rather than a lowercase call.
    assert build_purl(ecosystem, name, version) == expected


def test_scoped_npm_packages_round_trip() -> None:
    purl = build_purl("npm", "@babel/Core", "7.23.0")
    parsed = parse_purl(purl)
    assert parsed.ecosystem == "npm"
    assert parsed.name == "@babel/core"
    assert parsed.version == "7.23.0"


def test_versionless_purl_is_the_advisory_lookup_key() -> None:
    parsed = parse_purl("pkg:pypi/requests@2.31.0")
    assert parsed.purl_base == "pkg:pypi/requests"
    assert build_purl("PyPI", "requests") == "pkg:pypi/requests"


def test_parsing_normalises_an_unnormalised_purl() -> None:
    # A real SBOM may carry a non-normalised name; parsing must still land on
    # the canonical key.
    parsed = parse_purl("pkg:pypi/Flask_SQLAlchemy@3.1.1")
    assert parsed.name == "flask-sqlalchemy"
    assert parsed.purl == "pkg:pypi/flask-sqlalchemy@3.1.1"


def test_unknown_ecosystem_is_carried_not_guessed() -> None:
    # Refusing an unrecognised ecosystem would discard real data from a valid
    # SBOM, so the name is passed through untouched.
    assert normalise_name("SomeNewRegistry", "Thing.Name") == "Thing.Name"


def test_rubbish_is_rejected() -> None:
    with pytest.raises(ValueError, match="not a valid purl"):
        parse_purl("definitely-not-a-purl")
