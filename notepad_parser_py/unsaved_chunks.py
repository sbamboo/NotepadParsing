import json
from .errors import *
from .utils import read_uleb128, read_utf16_string, bytes_to_hex

class UnsavedChunk:
    def __init__(self):
        self.position = 0
        self.num_of_deletion = 0
        self.num_of_addition = 0
        self.data = None
        self.checksum = ""
        
    @classmethod
    def from_reader(cls, reader):
        chunk = cls()
        
        try:
            # Read position
            chunk.position = read_uleb128(reader)
            
            # Read number of deletions
            chunk.num_of_deletion = read_uleb128(reader)
            
            # Read number of additions
            chunk.num_of_addition = read_uleb128(reader)
            
            # Read data if there are additions
            if chunk.num_of_addition > 0:
                chunk.data = read_utf16_string(reader, chunk.num_of_addition)
            
            # Read checksum
            checksum = reader.read(4)
            if not checksum or len(checksum) != 4:
                raise ReadError("Failed to read checksum", "checksum")
            chunk.checksum = bytes_to_hex(checksum)
            
            return chunk
            
        except EOFError:
            raise EOFError()
        except Exception as e:
            raise ReadError(str(e), "UnsavedChunk")
            
    def to_dict(self):
        data = {
            'position': self.position,
            'num_of_deletion': self.num_of_deletion,
            'num_of_addition': self.num_of_addition,
            'checksum': self.checksum
        }
        if self.data is not None:
            data['data'] = self.data
        return data

class UnsavedChunks:
    def __init__(self):
        self.chunks = []
        
    @classmethod
    def from_reader(cls, reader):
        chunks = cls()
        
        try:
            while True:
                try:
                    chunk = UnsavedChunk.from_reader(reader)
                    chunks.chunks.append(chunk)
                except EOFError:
                    # If we have chunks already, this is a normal EOF
                    if chunks.chunks:
                        break
                    # If no chunks were read, raise NAError
                    raise NAError()
                except Exception as e:
                    # If we have chunks already, break the loop
                    if chunks.chunks:
                        break
                    # Otherwise propagate the error
                    raise GenericError(str(e), "UnsavedChunks.from_reader", 
                                     "Error during reading list of UnsavedChunk")
                    
            return chunks
            
        except NAError:
            raise
        except EOFError:
            # If we have chunks, return them
            if chunks.chunks:
                return chunks
            raise NAError()
        except Exception as e:
            # If we have chunks, return them
            if chunks.chunks:
                return chunks
            raise GenericError(str(e), "UnsavedChunks.from_reader", 
                             "Error during reading list of UnsavedChunk")
    
    def __str__(self):
        previous_addition = 0
        result = []
        
        for chunk in self.chunks:
            if chunk.num_of_addition > 0:
                if previous_addition == 0:
                    previous_addition = chunk.position
                    result.append(f"[{chunk.position}]:{chunk.data}")
                elif chunk.position == (previous_addition + 1):
                    result.append(chunk.data)
                    previous_addition = chunk.position
                else:
                    result.append(f",[{chunk.position}]:{chunk.data}")
                    previous_addition = chunk.position
            else:
                if previous_addition > 0:
                    previous_addition = previous_addition - 1
                result.append(f"<DEL:{chunk.position}>")
                
        return ''.join(result)
        
    def to_dict(self):
        return [chunk.to_dict() for chunk in self.chunks]