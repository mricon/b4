import pytest

from b4._textwidth import display_width, pad_display


@pytest.mark.parametrize(
    'text,expected',
    [
        pytest.param('hello', 5, id='ascii'),
        pytest.param('', 0, id='empty'),
        # Each CJK character is 2 columns wide
        pytest.param('戸田晃太', 8, id='cjk'),
        # U+FF21 FULLWIDTH LATIN CAPITAL LETTER A
        pytest.param('Ａ', 2, id='fullwidth-latin'),
        # BLACK STAR has east_asian_width 'A' (ambiguous); we treat it as 1
        # column, matching what western terminals render.
        pytest.param('★', 1, id='ambiguous-width-is-narrow'),
    ],
)
def test_display_width(text: str, expected: int) -> None:
    assert display_width(text) == expected


@pytest.mark.parametrize(
    'text,width,expected',
    [
        pytest.param('hello', 10, 'hello     ', id='ascii-padding'),
        # '戸田' = 4 display cols, pad to 10 = 6 spaces
        pytest.param('戸田', 10, '戸田      ', id='cjk-padding'),
        pytest.param('hello', 5, 'hello', id='no-padding-when-exact'),
        pytest.param('hello world', 5, 'hell…', id='truncate-when-over'),
        # '戸田晃太' = 8 display cols, truncate to 5: '戸田' (4) + ellipsis (1)
        pytest.param('戸田晃太', 5, '戸田…', id='truncate-cjk'),
        # 'K 戸田' = 1 + 1 + 2 + 2 = 6 display cols, pad to 10 = 4 spaces
        pytest.param('K 戸田', 10, 'K 戸田    ', id='mixed-padding'),
    ],
)
def test_pad_display(text: str, width: int, expected: str) -> None:
    result = pad_display(text, width)
    assert result == expected
    assert display_width(result) == width
