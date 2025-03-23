import json
from .errors import *
from .enums import Encoding, CRType
from .utils import (
    read_bool, read_uleb128, read_utf16_string, 
    bytes_to_hex, FileTime
)
from .unsaved_chunks import UnsavedChunks

class ConfigBlock:
    def __init__(self):
        self.word_wrap = False
        self.rtl = False
        self.show_unicode = False
        self.version = 0
        self.unknown0 = 0
        self.unknown1 = 0
        
    @classmethod
    def from_reader(cls, reader):
        config = cls()
        
        try:
            config.word_wrap = read_bool(reader)
            config.rtl = read_bool(reader)
            config.show_unicode = read_bool(reader)
            config.version = read_uleb128(reader)
            config.unknown0 = int.from_bytes(reader.read(1), 'little')
            config.unknown1 = int.from_bytes(reader.read(1), 'little')
            
            return config
            
        except Exception as e:
            raise ReadError(str(e), "ConfigBlock")
            
    def to_dict(self):
        return {
            'word_wrap': self.word_wrap,
            'rtl': self.rtl,
            'show_unicode': self.show_unicode,
            'version': self.version
        }

class NotepadTabStat:
    def __init__(self):
        self.tabstate_path = None
        self.signature = b'NP'
        self.seq_number = 0
        self.is_saved_file = False
        self.path_size = 1
        self.path = None
        self.file_size = None
        self.encoding = None
        self.cr_type = None
        self.last_write_time = None
        self.file_hash = None
        self.unknown1 = None
        self.cursor_start = None
        self.cursor_end = None
        self.config_block = ConfigBlock()
        self.file_content_size = 0
        self.file_content = "Hello :D"
        self.contain_unsaved_data = False
        self.checksum = "41414141"
        self.unsaved_chunks = None
        self.unsaved_chunks_str = None
        
    @classmethod
    def from_path(cls, path):
        try:
            with open(path, 'rb') as f:
                # Read first 2 bytes to check signature
                signature = f.read(2)
                if signature != b'NP':
                    raise SignatureError(signature.decode('ascii', errors='replace'))
                f.seek(0)  # Reset to start
                
                parsed = cls.from_reader(f)
                if hasattr(parsed,"tabstate_path"):
                    parsed.tabstate_path = path
                return parsed
        except SignatureError:
            # Not a TabState file, ignore it
            return None
        except Exception as e:
            raise FileOpenError(str(e), path)
            
    @classmethod
    def from_reader(cls, reader):
        tab = cls()
        
        try:
            # Read signature
            signature = reader.read(2)
            if signature != b'NP':
                raise SignatureError(signature.decode('ascii', errors='replace'))
                
            tab.signature = signature
            
            # Read sequence number
            tab.seq_number = read_uleb128(reader)
            
            # Read is_saved_file flag
            try:
                tab.is_saved_file = read_bool(reader)
            except (EOFError, ValueError, SignatureError):
                # If we can't read the saved flag, assume it's not a valid TabState file
                return None
            
            # Read path size
            try:
                tab.path_size = read_uleb128(reader)
            except (EOFError, ValueError):
                # If we can't read the path size, return what we have
                return tab
            
            if tab.is_saved_file:
                try:
                    # Read saved file specific data
                    tab.path = read_utf16_string(reader, tab.path_size)
                    tab.file_size = read_uleb128(reader)
                    
                    encoding_byte = reader.read(1)
                    if encoding_byte:
                        tab.encoding = Encoding.from_value(int.from_bytes(encoding_byte, 'little'))
                        
                    cr_type_byte = reader.read(1)
                    if cr_type_byte:
                        tab.cr_type = CRType.from_value(int.from_bytes(cr_type_byte, 'little'))
                        
                    tab.last_write_time = FileTime(read_uleb128(reader))
                    
                    # Read file hash
                    file_hash = reader.read(32)
                    if len(file_hash) == 32:
                        tab.file_hash = bytes_to_hex(file_hash)
                    
                    # Read unknown1
                    unknown1 = reader.read(2)
                    if len(unknown1) == 2:
                        tab.unknown1 = unknown1
                    
                    # Read cursor positions
                    tab.cursor_start = read_uleb128(reader)
                    tab.cursor_end = read_uleb128(reader)
                except (EOFError, ValueError):
                    # Return what we have if we hit EOF
                    return tab
                    
            else:
                try:
                    # Read unsaved file specific data
                    tab.cursor_start = read_uleb128(reader)
                    tab.cursor_end = read_uleb128(reader)
                except (EOFError, ValueError):
                    # Return what we have if we hit EOF
                    return tab
                
            try:
                # Read config block
                tab.config_block = ConfigBlock.from_reader(reader)
                
                # Read file content
                tab.file_content_size = read_uleb128(reader)
                tab.file_content = read_utf16_string(reader, tab.file_content_size)
            except (EOFError, ValueError):
                # Return what we have if we hit EOF
                return tab
            
            try:
                # Read contain_unsaved_data flag
                tab.contain_unsaved_data = read_bool(reader)
                
                # Read checksum
                checksum = reader.read(4)
                if len(checksum) == 4:
                    tab.checksum = bytes_to_hex(checksum)
                
                # Try to read unsaved chunks
                try:
                    tab.unsaved_chunks = UnsavedChunks.from_reader(reader)
                    if tab.unsaved_chunks:
                        tab.unsaved_chunks_str = str(tab.unsaved_chunks)
                except (EOFError, NAError, Exception):
                    # It's okay if there are no unsaved chunks
                    pass
                    
            except (EOFError, ValueError, Exception):
                # It's okay if we can't read these optional fields
                pass
            
            return tab
            
        except SignatureError:
            # Not a TabState file
            return None
        except Exception as e:
            # For any other error, return what we have parsed so far
            return tab
        
    def to_dict(self):
        data = {
            'is_saved_file': self.is_saved_file,
            'path_size': self.path_size,
            'config_block': self.config_block.to_dict(),
            'file_content_size': self.file_content_size,
            'file_content': self.file_content,
            'contain_unsaved_data': self.contain_unsaved_data,
            'checksum': self.checksum
        }
        
        if self.tabstate_path:
            data['tabstate_path'] = self.tabstate_path
        if self.path:
            data['path'] = self.path
        if self.file_size is not None:
            data['file_size'] = self.file_size
        if self.encoding:
            if hasattr(self.encoding,"name"):
                data['encoding'] = self.encoding.name
            else:
                data['encoding'] = None
        if self.cr_type:
            if hasattr(self.cr_type,"name"):
                data['cr_type'] = self.cr_type.name
            else:
                data['cr_type'] = None
        if self.last_write_time:
            data['last_write_time'] = str(self.last_write_time)
        if self.file_hash:
            data['file_hash'] = self.file_hash
        if self.cursor_start is not None:
            data['cursor_start'] = self.cursor_start
        if self.cursor_end is not None:
            data['cursor_end'] = self.cursor_end
        if self.unsaved_chunks:
            data['unsaved_chunks'] = self.unsaved_chunks.to_dict()
        if self.unsaved_chunks_str:
            data['unsaved_chunks_str'] = self.unsaved_chunks_str
            
        return data
        
    def to_json(self, pretty=False):
        if pretty:
            return json.dumps(self.to_dict(), indent=2)
        return json.dumps(self.to_dict())