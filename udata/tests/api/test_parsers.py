from udata.api.parsers import diacritic_insensitive_regex


def test_diacritic_insensitive_regex_matches_both_directions():
    """The accent can sit on either side, or on neither."""
    stored = "Agência para a Reforma Tecnológica do Estado"

    assert diacritic_insensitive_regex("agencia").search(stored)
    assert diacritic_insensitive_regex("agência").search(stored)
    assert diacritic_insensitive_regex("AGENCIA").search(stored)

    # And an accent-less stored value is still found by an accented query.
    assert diacritic_insensitive_regex("tecnológica").search("Reforma Tecnologica")


def test_diacritic_insensitive_regex_escapes_metacharacters():
    """A query is matched literally: it comes from the URL."""
    assert not diacritic_insensitive_regex("a.*b").search("aXXb")
    assert diacritic_insensitive_regex("a.*b").search("literal a.*b here")

    # These would raise if they reached the engine unescaped.
    for query in ("(", "[", "\\", "*", "^", "$", "(a+)+$", "a-b"):
        assert diacritic_insensitive_regex(query).pattern is not None


def test_diacritic_insensitive_regex_preserves_non_latin():
    """Folding to ASCII would empty the pattern, and an empty pattern matches everything."""
    pattern = diacritic_insensitive_regex("日本")

    assert pattern.search("日本政府")
    assert not pattern.search("Agência para a Reforma Tecnológica do Estado")


def test_diacritic_insensitive_regex_matches_combining_marks_only_query_literally():
    """A query that folds to nothing falls back to a literal match, never to match-all."""
    pattern = diacritic_insensitive_regex("́")

    assert not pattern.search("Comissão")
