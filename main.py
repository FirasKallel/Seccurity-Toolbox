from utils import *
if __name__ == '__main__':
    h = hash_msg("carson", "SHA512")
    print(search_for_original(h, "SHA512"))
