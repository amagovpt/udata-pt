import re
import unicodedata

from udata.api import api

# Base letter -> every diacritic variant it should match. Used to build a regex that
# matches regardless of which side carries the accent.
_DIACRITIC_VARIANTS = {
    "a": "aàáâãäå",
    "c": "cç",
    "e": "eèéêë",
    "i": "iìíîï",
    "n": "nñ",
    "o": "oòóôõö",
    "u": "uùúûü",
    "y": "yýÿ",
}


def normalize_search_query(query: str) -> str:
    """Strip diacritics from a query, down to ASCII.

    Only useful ahead of a `search_text()` call, where Mongo's text index already folds
    the diacritics on the indexed side. It does NOT make an accent-less query match an
    accented stored value on its own -- the stored side keeps its accents, so comparing
    the two with `icontains` fails in both directions. Use `diacritic_insensitive_regex`
    for that.
    """
    return unicodedata.normalize("NFD", query).encode("ascii", "ignore").decode("ascii")


def _fold_diacritics(text: str) -> str:
    """Drop the combining marks, keeping every other character.

    Deliberately not `normalize_search_query`: encoding to ASCII drops whole scripts, so
    a query like "日本" folds to the empty string -- and an empty pattern matches every
    document. Dropping category `Mn` leaves non-Latin text intact, the way the INE
    harvester's own tag normalisation does.
    """
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn").lower()


def diacritic_insensitive_regex(query: str) -> re.Pattern:
    """Build a case- and accent-insensitive regex matching `query` as a substring.

    MongoEngine's `icontains` compiles to an accent-sensitive `$regex`, so "agencia"
    never matches the stored "Agência" and, once the query is folded, "agência" stops
    matching it too. Folding the query to its base letters and expanding each of them to
    a character class covering its variants makes the match work whichever side carries
    the accent.

    Every character that is not an expandable base letter goes through `re.escape`, so a
    query is always matched literally: the value comes from the URL, and an unescaped
    regex built from it would be a denial-of-service vector.
    """
    base = _fold_diacritics(query)
    if not base:
        # Nothing survived the fold (a query of combining marks alone). An empty pattern
        # would match every document, so match the original text literally instead.
        return re.compile(re.escape(query), re.IGNORECASE)
    pattern = "".join(
        f"[{_DIACRITIC_VARIANTS[ch]}]" if ch in _DIACRITIC_VARIANTS else re.escape(ch)
        for ch in base
    )
    return re.compile(pattern, re.IGNORECASE)


class ModelApiParser:
    """This class allows to describe and customize the api arguments parser behavior."""

    sorts = {}

    def __init__(self, paginate=True):
        self.parser = api.parser()
        # q parameter
        self.parser.add_argument("q", type=str, location="args", help="The search query")
        # Sort arguments
        keys = list(self.sorts)
        choices = keys + ["-" + k for k in keys]
        help_msg = "The field (and direction) on which sorting apply"
        self.parser.add_argument("sort", type=str, location="args", choices=choices, help=help_msg)
        if paginate:
            self.parser.add_argument(
                "page", type=int, location="args", default=1, help="The page to display"
            )
            self.parser.add_argument(
                "page_size", type=int, location="args", default=20, help="The page size"
            )

    def parse(self):
        args = self.parser.parse_args()
        if args["sort"]:
            if args["sort"].startswith("-"):
                # Keyerror because of the '-' character in front of the argument.
                # It is removed to find the value in dict and added back.
                arg_sort = args["sort"][1:]
                args["sort"] = "-" + self.sorts[arg_sort]
            else:
                args["sort"] = self.sorts[args["sort"]]
        return args
