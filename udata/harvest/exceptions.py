class HarvestException(Exception):
    """Base class for all harvest exception"""

    pass


class HarvestSkipException(HarvestException):
    """Raised when an item is skipped"""

    pass


class HarvestValidationError(HarvestException):
    """Raised when an harvested item is invalid"""

    pass


class HarvestRemoteBlocked(HarvestException):
    """Raised when the remote source answers with an anti-bot challenge instead of content"""

    pass
