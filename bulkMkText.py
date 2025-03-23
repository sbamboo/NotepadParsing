import os
import sys

def create_output_folder(output_folder):
    # Ensure the output folder exists, create it recursively
    os.makedirs(output_folder, exist_ok=True)

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
                output_file_path = os.path.join(output_folder, file + '.txt')

                # Open the file in binary mode
                with open(file_path, 'rb') as f:
                    file_data = f.read()

                try:
                    # Try to decode the binary data into a string
                    decoded_data = file_data.decode(encoding, errors='replace')
                except Exception as e:
                    print(f"Error decoding file {file_path}: {e}")
                    decoded_data = file_data.decode(encoding, errors='replace')

                # Save the decoded content to the output folder
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
    create_output_folder(output_folder)

    # Process the files
    process_files(input_folder, output_folder, extensions, encoding)

if __name__ == '__main__':
    main()
