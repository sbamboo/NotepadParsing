class NotepadError(Exception):
    """Base exception for Notepad parser errors"""
    pass

class GenericError(NotepadError):
    def __init__(self, error, function, additional):
        self.message = f"Encountered an error. Error: '{error}', Function: '{function}', Additional: '{additional}'"
        super().__init__(self.message)

class SignatureError(NotepadError):
    def __init__(self, found):
        self.message = f"File signature doesn't match the correct TabState file format. Expected 'NP', found '{found}'"
        super().__init__(self.message)

class ReadError(NotepadError):
    def __init__(self, error, field):
        self.message = f"Unable to read data. Error: '{error}', Field: '{field}'"
        super().__init__(self.message)

class ReadErrorWithSize(NotepadError):
    def __init__(self, error, field, size):
        self.message = f"Unable to read data. Error: '{error}', Field: '{field}', Size: '{size}'"
        super().__init__(self.message)

class UnexpectedValue(NotepadError):
    def __init__(self, expected, found, field):
        self.message = f"Unexpected value found. Expected: '{expected}', Found: '{found}', Field: '{field}'"
        super().__init__(self.message)

class EOFError(NotepadError):
    def __init__(self):
        self.message = "EOF Reached"
        super().__init__(self.message)

class NAError(NotepadError):
    def __init__(self):
        self.message = "No data to parse"
        super().__init__(self.message)

class FileOpenError(NotepadError):
    def __init__(self, error, path):
        self.message = f"Error while opening a file. ERROR: '{error}', PATH: '{path}'"
        super().__init__(self.message)

class CLIError(NotepadError):
    def __init__(self, error, msg):
        self.message = f"CLI error. ERROR: '{error}', MSG: '{msg}'"
        super().__init__(self.message)