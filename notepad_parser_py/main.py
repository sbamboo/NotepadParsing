#!/usr/bin/env python3
import argparse
import glob
import json
import logging
import sys
from .notepad_parser import NotepadTabStat

def setup_logging(level_str):
    levels = {
        'trace': logging.DEBUG,
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'error': logging.ERROR,
        'quiet': logging.CRITICAL
    }
    level = levels.get(level_str.lower(), logging.INFO)
    
    logging.basicConfig(
        format='%(asctime)s [%(threadName)s:%(lineno)d] %(levelname)s: %(message)s',
        level=level,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def main():
    parser = argparse.ArgumentParser(
        description='Parse Windows Notepad TabState files',
        epilog='Reference: https://u0041.co/posts/articals/exploring-windows-artifacts-notepad-files/'
    )
    
    parser.add_argument(
        'input_file',
        nargs='?',
        default="C:\\Users\\*\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\????????-????-????-????-????????????.bin",
        help='Path to the files to parse. Accepts glob.'
    )
    
    parser.add_argument(
        '-f', '--output-format',
        choices=['jsonl', 'csv'],
        default='jsonl',
        help='Specify the output format'
    )
    
    parser.add_argument(
        '-o', '--output-path',
        default='stdout',
        help='Specify the output file'
    )
    
    parser.add_argument(
        '-l', '--log-level',
        choices=['trace', 'debug', 'info', 'error', 'quiet'],
        default='quiet',
        help='Level for logs'
    )
    
    args = parser.parse_args()
    
    setup_logging(args.log_level)
    
    output_file = sys.stdout if args.output_path == 'stdout' else open(args.output_path, 'w')
    
    try:
        for file_path in glob.glob(args.input_file):
            try:
                data = NotepadTabStat.from_path(file_path)
                if args.output_format == 'jsonl':
                    print(data.to_json(), file=output_file)
                else:
                    # TODO: Implement CSV output
                    logging.error("CSV output not yet implemented")
                    
            except Exception as e:
                logging.error(f"Error processing file '{file_path}': {str(e)}")
                
    finally:
        if output_file is not sys.stdout:
            output_file.close()

if __name__ == '__main__':
    main()