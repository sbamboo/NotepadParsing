import struct
from datetime import datetime, timezone

def read_bool(reader):
    """Read a boolean value from the reader"""
    try:
        data = reader.read(1)
        if not data:
            raise EOFError("End of file reached")
        
        value = data[0]
        # Only accept 0 or 1 as valid boolean values
        if value == 0x0:
            return False
        elif value == 0x1:
            return True
        else:
            # If we get an invalid value, assume this isn't a valid TabState file
            raise SignatureError(f"Invalid boolean value: {value}")
    except EOFError:
        raise
    except Exception as e:
        raise ValueError(f"Failed to read boolean: {str(e)}")

def read_uleb128(reader):
    """Read an unsigned LEB128 encoded number"""
    try:
        result = 0
        shift = 0
        
        while True:
            byte = reader.read(1)
            if not byte:
                raise EOFError("End of file reached")
            
            byte = byte[0]
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
            if shift > 63:  # Prevent integer overflow
                raise ValueError("ULEB128 value too large")
            
        return result
    except EOFError:
        raise
    except Exception as e:
        raise ValueError(f"Failed to read ULEB128: {str(e)}")

def read_utf16_string(reader, size=None):
    """Read a UTF-16 encoded string"""
    try:
        if size is None:
            # Read until null terminator
            chars = []
            while True:
                char = reader.read(2)
                if not char or char == b'\x00\x00':
                    break
                chars.append(char)
            return b''.join(chars).decode('utf-16le')
        else:
            # Read specified number of characters
            data = reader.read(size * 2)
            if len(data) < size * 2:
                raise EOFError("Unexpected end of file while reading string")
            return data.decode('utf-16le')
    except EOFError:
        raise
    except Exception as e:
        raise ValueError(f"Failed to read UTF-16 string: {str(e)}")

def bytes_to_hex(data):
    """Convert bytes to hex string"""
    return ''.join(f'{b:02x}' for b in data)

class FileTime:
    def __init__(self, timestamp):
        self.timestamp = timestamp
        
    def to_datetime(self):
        """Convert Windows FILETIME to datetime"""
        # Windows FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
        WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
        seconds = self.timestamp / 10_000_000  # Convert to seconds
        return WINDOWS_EPOCH.fromtimestamp(seconds)
    
    def __str__(self):
        return str(self.to_datetime())