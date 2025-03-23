# Notepad Cache Parsing & Reading

The goal of this project is to read and parse the new Windows 11, Notepad.exe Cache.

## Python Library
`/notepad_parser_py` contains a python translation of the rust library [AbdulRhmanAlfaifi/notepad_parser](https://github.com/AbdulRhmanAlfaifi/notepad_parser/tree/main/src)

## Scripts
The `bulkMkText...` files are scripts for reading the files or using `notepad_parser_py`.<br><br>
Al of the scripts have the same usage:<br>
`python3 <script>.py <input_folder> <output_folder> <extensions> [<encoding>]`<br>
- `<input_folder>` is the folder with al the files you want to convert. *(must exists)*
- `<output_folder>` is where you want the script to place the converted files. *(may not exists, will attempt create if not)*
- `<extensions>` is a comma sepparated list of file extensions with dots ex: `.bin` or `.bin,.bin.bak` *(".bin", ".bin.bak")*
- `<encoding>` is the encoding to save the converted file as *(defaulted to `utf-8`)*
<br><br>

| **Script** | **Description** |
|------------|-----------------|
| `bulkMkText.py` | Reads al the files, attempts to convert them to *encoding* and writes. |
| `bulkMkText_Clean.py` | Reads al the files, attempts to convert them to *encoding*, cleans invalid chars and writes. |
| `bulkMkText_Parsed.py` | Reads al the files, parses them using `notepad_parser_py` and writes assembled text content. |
| `bulkMkText_Parsed_JSON.py` | Reads al the files, parses them using `notepad_parser_py` and writes the JSON of the parsed data. |