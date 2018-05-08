import random
import os


class FUZZ_STYLE:
    NONE = 0 # none
    SNIPER = 1  # Load data from file (Manual Fuzzing)
    BUFFER_BUSTER = 2 # Generate large data for target fields
    MUTATE = 3  # Morph current data. This is good for parsing bugs

class riscy_fuzzer:
    def __init__(self):
        self.hFile = None
        self.fuzz_style = FUZZ_STYLE.NONE
        self.fuzz_severity = 0

    def fuzz_int(self, low=0, high=0xFFFFFFFF):
        return random.randint(low, high)

    def fuzz_str(self, length):
        return os.urandom(length)
    
    def mutate_str(self, _string):
        str_len = len(_string)
        iterations = int(str_len*self.fuzz_severity)
        new_chars = list(_string)
        for _ in range(0, iterations):
            index = random.randrange(0, str_len-1)
            new_chars[index] = chr(random.randrange(0, 0xff))
        return "".join(new_chars)
        
    def load_sniper_data(self):
        if self.hFile is None:
            self.hFile = open('sniper_file', 'rb')
        data = self.hFile.read()
        self.hFile.seek(0)
        return data