try:
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs
from httpie_apisix_hmac import _build_canonical_query_string


def test_parse_qs():
    url_str = "/bidding/win-bid?quote&city=%E8%A1%A1%E6%B0%B4&q=%E5%8C%BB%E9%99%A2"

    url = urlparse(url_str)

    qs = parse_qs(url.query, keep_blank_values=True)

    print(qs)
    assert qs["city"] == ["衡水"]
    assert qs["q"] == ["医院"]
    assert qs["quote"] == [""]


def test_build_canonical_query_string():
    query = "quote&city=%E8%A1%A1%E6%B0%B4&city=%E8%A1%A1%E6%B0%B42&q=%E5%8C%BB%E9%99%A2"
    result = _build_canonical_query_string(query)
    assert result == "city=%E8%A1%A1%E6%B0%B4&city=%E8%A1%A1%E6%B0%B42&q=%E5%8C%BB%E9%99%A2&quote="
