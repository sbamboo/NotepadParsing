import unittest
import os
from glob import glob
from ..notepad_parser import NotepadTabStat

SAMPLES_DIR = "samples"

def get_paths_from_glob(glob_pattern):
    paths = glob(glob_pattern)
    if not paths:
        raise ValueError("Glob list is empty!")
    return paths

def check_rtl(data):
    return data.config_block.rtl

def check_word_wrap(data):
    return data.config_block.word_wrap

def check_unsaved_chunks(data):
    return data.unsaved_chunks is not None

def check_is_saved(data):
    return data.is_saved_file

def check_contain_unsaved_data(data):
    return data.contain_unsaved_data

class TestNotepadParser(unittest.TestCase):
    def test_tabstate_no_path(self):
        data = bytes([
            0x4E, 0x50, 0x00, 0x00, 0x01, 0x15, 0x15, 0x01, 0x00, 0x00, 0x02, 0x01, 0x01, 0x15, 
            0x50, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00, 0x77, 0x00, 0x6F, 0x00, 0x72, 0x00, 
            0x64, 0x00, 0x20, 0x00, 0x69, 0x00, 0x73, 0x00, 0x20, 0x00, 0x61, 0x00, 0x62, 0x00, 
            0x63, 0x00, 0x64, 0x00, 0x20, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x00, 
            0x01, 0xDD, 0xBD, 0x91, 0xE1
        ])
        from io import BytesIO
        reader = BytesIO(data)
        result = NotepadTabStat.from_reader(reader)
        json_data = result.to_json(pretty=True)
        print(json_data)
        
    def test_saved_english_unsaved_mod(self):
        pattern = os.path.join(SAMPLES_DIR, "saved/english/unsaved_mod/*.bin")
        for path in get_paths_from_glob(pattern):
            data = NotepadTabStat.from_path(path)
            self.assertTrue(check_unsaved_chunks(data), 
                          "Didn't extract unsaved data chunk")
            self.assertTrue(check_is_saved(data),
                          "is_saved_file is reported to be unset, but it should be")
            
    def test_saved_english_rtl_unset(self):
        pattern = os.path.join(SAMPLES_DIR, "saved/english/rtl_unset/*.bin")
        for path in get_paths_from_glob(pattern):
            data = NotepadTabStat.from_path(path)
            self.assertFalse(check_rtl(data),
                           "RTL is reported to be set, but it shouldn't")
            self.assertTrue(check_word_wrap(data),
                          "WordWrap is reported to be unset, but it should be")
            self.assertTrue(check_is_saved(data),
                          "is_saved_file is reported to be unset, but it should be")

if __name__ == '__main__':
    unittest.main()