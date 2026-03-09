from b4.review_tui._common import display_width, pad_display


class TestDisplayWidth:
    """Tests for display_width()."""

    def test_ascii(self) -> None:
        assert display_width('hello') == 5

    def test_empty(self) -> None:
        assert display_width('') == 0

    def test_cjk(self) -> None:
        # Each CJK character is 2 columns wide
        assert display_width('戸田晃太') == 8

    def test_mixed(self) -> None:
        # 4 CJK chars (8) + 1 space (1) + 3 ASCII (3) = 12
        assert display_width('戸田晃太 abc') == 12

    def test_fullwidth_latin(self) -> None:
        # U+FF21 FULLWIDTH LATIN CAPITAL LETTER A
        assert display_width('\uff21') == 2

    def test_emoji(self) -> None:
        # Most emoji have east_asian_width 'W'
        assert display_width('\u2605') >= 1  # BLACK STAR


class TestPadDisplay:
    """Tests for pad_display()."""

    def test_ascii_padding(self) -> None:
        result = pad_display('hello', 10)
        assert result == 'hello     '
        assert len(result) == 10

    def test_cjk_padding(self) -> None:
        # '戸田' = 4 display cols, pad to 10 = 6 spaces
        result = pad_display('戸田', 10)
        assert display_width(result) == 10
        assert result == '戸田      '

    def test_no_padding_when_exact(self) -> None:
        result = pad_display('hello', 5)
        assert result == 'hello'

    def test_truncate_when_over(self) -> None:
        result = pad_display('hello world', 5)
        assert result == 'hell\u2026'
        assert display_width(result) == 5

    def test_truncate_long_name(self) -> None:
        result = pad_display('Bastien Curutchet (Schneider Electric)', 30)
        assert display_width(result) == 30
        assert result.endswith('\u2026')

    def test_truncate_cjk(self) -> None:
        # '戸田晃太' = 8 display cols, truncate to 5: '戸田' (4) + ellipsis (1)
        result = pad_display('戸田晃太', 5)
        assert display_width(result) == 5
        assert result.endswith('\u2026')

    def test_mixed_padding(self) -> None:
        # 'K 戸田' = 1 + 1 + 2 + 2 = 6 display cols, pad to 10 = 4 spaces
        result = pad_display('K 戸田', 10)
        assert display_width(result) == 10
