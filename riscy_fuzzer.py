import random
import os

class riscy_fuzzer:
    def fuzz_int(self, low=0, high=0xFFFFFFFF):
        return int(random.randrange(low, high))

    def fuzz_str(self, length):
        return os.urandom(length)
    
    def mutate_str(self, _string, severity=.2, expansion=0):
        str_len = len(_string)
        iterations = int(str_len*severity)
        new_chars = list(_string)
        for _ in range(0,iterations):
            index = random.randrange(0, str_len)
            new_chars[index] = chr(random.randrange(0, 0xff))
        expansion_size = int(expansion*str_len)
        
        for i in range(0,expansion_size):
            new_chars.insert(random.randrange(0,(str_len-1)+i), chr(random.randrange(0,0xff)))
        return "".join(new_chars)