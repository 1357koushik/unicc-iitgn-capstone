"""The error the web app turns into an answer for the user."""


class ScanError(Exception):
    """The request cannot be done. status_code is the HTTP code to answer with."""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
