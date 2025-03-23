from enum import Enum

class Encoding(Enum):
    ANSI = 0x01
    UTF16LE = 0x02
    UTF16BE = 0x03
    UTF8BOM = 0x04
    UTF8 = 0x05
    
    @classmethod
    def from_value(cls, value):
        try:
            return cls(value)
        except ValueError:
            return f"UNKNOWN({value})"

class CRType(Enum):
    CRLF = 0x1
    CR = 0x2
    LF = 0x3
    
    @classmethod
    def from_value(cls, value):
        try:
            return cls(value)
        except ValueError:
            return f"UNKNOWN({value})"