from notepad_parser_py import NotepadTabStat

import os
import sys
import re
import string
import json

def get_unique_filepath(filepath):
    # Extract the directory and the file name (without extension)
    directory, filename = os.path.split(filepath)
    name, extension = os.path.splitext(filename)

    # Start with an index of 2
    i = 2

    # Loop until a unique filename is found
    while os.path.exists(filepath):
        # Create a new filename by appending the index to the name
        new_filename = f"{name}_{i}{extension}"
        filepath = os.path.join(directory, new_filename)
        i += 1

    return filepath

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

                # Convert the file
                data = NotepadTabStat.from_path(file_path)
                
                if data == None:
                    print(f"Empty data for {file_path}")
                    continue

                # Convert to dict
                parsed_data = data.to_dict()

                # Get filename
                filename = os.path.basename(file_path)
                if parsed_data.get("path",None) is not None:
                    filename = os.path.basename(parsed_data["path"])

                # Conver to json
                json_data_string = json.dumps(parsed_data, indent=4)

                # Sanitize the filename
                sanitized_filename = sanitize_filename(filename+".json")
                sanitized_filename = get_unique_filepath(sanitized_filename)
                output_file_path = os.path.join(output_folder, sanitized_filename)

                # Save the cleaned content to the output folder
                with open(output_file_path, 'w', encoding=encoding) as output_file:
                    output_file.write(json_data_string)

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
