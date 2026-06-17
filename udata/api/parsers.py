import re
import unicodedata

from udata.api import api

# Base letter -> every diacritic variant we want it to match. Used to build
# accent-insensitive regexes so that accent-less input ('agencia') matches
# accented stored values ('Agência') and vice-versa.
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
    """Strip diacritics so accent-less input (e.g. 'agencia') matches accented names."""
    return unicodedata.normalize("NFD", query).encode("ascii", "ignore").decode("ascii")


def diacritic_insensitive_regex(query: str) -> re.Pattern:
    """Build a case- and accent-insensitive regex matching ``query`` as a substring.

    MongoEngine ``__icontains`` compiles to an accent-sensitive ``$regex``, so
    'agencia' never matches the stored 'Agência'. Here we fold the query to its
    accent-less base and expand each base letter to a character class covering
    all its diacritic variants, yielding a regex that matches regardless of the
    accents present on either side (query or stored value).
    """
    base = normalize_search_query(query).lower()
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
