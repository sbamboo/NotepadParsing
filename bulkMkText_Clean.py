import os
import sys
import re

import string

import struct

def extract_notepad_text(binary_data):
    try:
        # Search for the text content section in the binary data
        # Typically, the content is stored in UTF-16LE, which is a fixed-width encoding

        # A simple way to extract the content:
        # Iterate through the binary data and attempt to find the UTF-16LE encoded content.
        
        # Try searching from the end of the header information (approx offset 28-32) onwards
        start_offset = 32  # Let's assume we start looking after the initial metadata header
        content_bytes = bytearray()
        
        # Read bytes and try to accumulate valid UTF-16LE content
        for i in range(start_offset, len(binary_data), 2):
            # Read the current 2 bytes
            byte_pair = binary_data[i:i+2]
            
            # If it's a valid UTF-16LE character (i.e., not a padding or null byte)
            if len(byte_pair) == 2:
                content_bytes.extend(byte_pair)
            
            # Stop when we hit a null character (end of string)
            if byte_pair == b'\x00\x00':
                break

        # Now decode the collected content as UTF-16LE
        content_text = content_bytes.decode('utf-16le')
        
        return content_text
    
    except UnicodeDecodeError as e:
        raise ValueError(f"Error decoding content as UTF-16LE: {e}")

def sanitize_filename(filename):
    # Trim all null bytes first
    filename = filename.replace('\x00', '')
    
    # Remove invalid characters that are not allowed in Windows filenames
    sanitized_filename = re.sub(r'[<>:"/\\|?*]', '_', filename)  # Replace invalid characters with '_'
    # Remove other control characters, including \x0b (vertical tab)
    sanitized_filename = ''.join(c for c in sanitized_filename if c in string.printable and not c.isspace() or c == ' ')
    sanitized_filename = sanitized_filename.strip()
    # Ensure filename is not a reserved name (case insensitive)
    reserved_filenames = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", 
                           "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}
    if sanitized_filename.upper() in reserved_filenames:
        sanitized_filename = f"_{sanitized_filename}_"
    return sanitized_filename

def process_files(input_folder, output_folder, extensions, encoding):
    # Keep track of whether any files were processed
    files_processed = False
    found_files = []  # To store the names of files found in the input folder

    # Walk through the directory and process files
    for root, _, files in os.walk(input_folder):
        for file in files:
            found_files.append(file)  # Add every file to the list
            # Check if the file extension matches one of the specified ones
            if any(file.endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                
                # Open the file in binary mode and read the first 20 characters for naming
                with open(file_path, 'rb') as f:
                    binary_data = f.read()

                try:
                    decoded_data = extract_notepad_text(binary_data)
                except Exception as e:
                    print(e)
                    continue

                # Generate output filename based on the first 20 characters of the content
                output_file_name = decoded_data[:50].replace('\n', ' ').replace('\r', '') + '.txt'
                # Sanitize the filename
                sanitized_filename = sanitize_filename(output_file_name)
                output_file_path = os.path.join(output_folder, sanitized_filename)

                # Save the cleaned content to the output folder
                with open(output_file_path, 'w', encoding=encoding) as output_file:
                    output_file.write(decoded_data)
                print(f"Processed: {file_path} -> {output_file_path}")
                files_processed = True  # Mark that we processed a file

    # If no files were processed, print a message and list the found files
    if not files_processed:
        print("No files to process with the given extensions.")
        if found_files:
            print("The following files were found in the input folder:")
            for file in found_files:
                print(f"- {file}")

def main():
    # Validate input arguments
    if len(sys.argv) < 4:
        print("Usage: bulkMkText.py <input-folder> <output-folder> <comma-sepparated-lists-of-file-extensions-with-dots> [<optional-encoding-else-utf8>]")
        sys.exit(1)
    
    input_folder = os.path.abspath(sys.argv[1])  # Convert to absolute path
    output_folder = os.path.abspath(sys.argv[2])  # Convert to absolute path
    extensions = sys.argv[3].split(',')  # List of file extensions
    encoding = sys.argv[4] if len(sys.argv) > 4 else "utf-8"  # Default encoding if not provided
    
    # Check if the input folder exists
    if not os.path.exists(input_folder):
        print(f"Warning: The input folder '{input_folder}' does not exist.")
        sys.exit(1)

    # Create the output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)

    # Process the files
    process_files(input_folder, output_folder, extensions, encoding)

if __name__ == '__main__':
    main()
