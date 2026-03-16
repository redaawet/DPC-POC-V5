def test_stdlib_tokenize_still_imports() -> None:
    import tokenize

    assert hasattr(tokenize, "EXACT_TOKEN_TYPES")
