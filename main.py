from os import system, name
from utils import *
from getpass import getpass


def clear():
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')


def menu_choice(mini: int, maxi: int):
    while True:
        try:
            choice = int(input("Votre choix: "))
        except ValueError:
            print("Veuillez saisir un chiffre entre " + str(mini) + " et " + str(maxi))
        else:
            if maxi >= choice >= mini:
                break
            else:
                print("Veuillez saisir un chiffre entre " + str(mini) + " et " + str(maxi))
    return choice


def print_title():
    print("-----------------------------------------------")
    print("     OUTIL SSI_INSAT POUR LA CRYPTOGRAPHIE     ")
    print("-----------------------------------------------\n")


def print_main_menu():
    print("-----------------------------------------------")
    print("1. Codage et décodage d'un message")
    print("2. Hashage d'un message")
    print("3. Craquage d'un message hashé")
    print("4. Chiffrement et déchiffrement symétrique")
    print("5. Chiffrement et déchiffrement asymétrique")
    print("6. Quitter")
    print("-----------------------------------------------")
    return menu_choice(1, 6)


def encoding_menu():
    ENCODING_BASES = {
        1: 64,
        2: 32,
        3: 16
    }
    print("-----------------------------------------------")
    print("1. Coder un message")
    print("2. Décoder un message")
    print("-----------------------------------------------")
    choice = menu_choice(1, 2)
    if choice == 1:
        print("-----------------------------------------------")
        print("1. Base64")
        print("2. Base32")
        print("3. Base16")
        print("-----------------------------------------------")
        sub_choice = menu_choice(1, 3)
        print("-----------------------------------------------")
        message = input("Veuillez saisir votre message: ")
        print("Le message codé est:")
        print(encoding_utils.code(message, ENCODING_BASES[sub_choice]))
        print("-----------------------------------------------")
    elif choice == 2:
        print("-----------------------------------------------")
        print("1. Base64")
        print("2. Base32")
        print("3. Base16")
        print("-----------------------------------------------")
        sub_choice = menu_choice(1, 3)
        print("-----------------------------------------------")
        message = input("Veuillez saisir le message à decoder: ")
        print("Le message decodé est:")
        print(encoding_utils.decode(message, ENCODING_BASES[sub_choice]))
        print("-----------------------------------------------")
    input("Tapez sur Entrée pour continuer...")


def hash_menu():
    AVAILABLE_HASHES = {
        1: "SHA256",
        2: "SHA512",
        3: "BLAKE2b",
        4: "BLAKE2s",
        5: "MD5"
    }
    print("-----------------------------------------------")
    print("1. SHA256")
    print("2. SHA512")
    print("3. BLAKE2b")
    print("4. BLAKE2s")
    print("5. MD5")
    print("-----------------------------------------------")
    choice = menu_choice(1, 5)
    print("-----------------------------------------------")
    message = input("Veuillez saisir le message: ")
    print("Le message hashé est: ")
    print(hashing_utils.hash_msg(message, AVAILABLE_HASHES[choice]))
    print("-----------------------------------------------")
    input("Tapez sur Entrée pour continuer...")


def brute_force_menu():
    AVAILABLE_HASHES = {
        1: "SHA256",
        2: "SHA512",
        3: "BLAKE2b",
        4: "BLAKE2s",
        5: "MD5"
    }
    print("-----------------------------------------------")
    print("1. SHA256")
    print("2. SHA512")
    print("3. BLAKE2b")
    print("4. BLAKE2s")
    print("5. MD5")
    print("-----------------------------------------------")
    hash_algo_choice = menu_choice(1, 5)
    print("-----------------------------------------------")
    hashed = input("Veuillez saisir le hashé: ")
    d = input("Doner un dicionnaire de mots[Dictionnaire de mots par default]: ")
    if d:
        result = brute_force_utils.search_for_original(hashed, AVAILABLE_HASHES[hash_algo_choice], d)
    else:
        result = brute_force_utils.search_for_original(hashed, AVAILABLE_HASHES[hash_algo_choice])
    if result:
        print("Le message original est:")
        print(result)
    else:
        print("L'algo de hash est incorrect ou le mot n'apparait pas dans le dictionnaire utilisé ")
    print("-----------------------------------------------")
    input("Tapez sur Entrée pour continuer...")


def get_password():
    while True:
        print("Veuillez saisir le mot de passe:")
        password = getpass("")
        print("Veuillez confirmer le mot de passe:")
        confirm_pwd = getpass("")
        if password == confirm_pwd:
            break
        else:
            print("Les mots de passe ne sont pas identiques. Veuillez réessayer...")
    return password


def symmetric_menu():
    AVAILABLE_ALGO = {
        1: aes_utils,
        2: des_utils,
        3: blowfish_utils,
        4: cast_utils
    }
    KEY_SIZE = {
        1: 128,
        2: 256
    }
    print("-----------------------------------------------")
    print("1. Chiffrement")
    print("2. Déchiffrement")
    print("-----------------------------------------------")
    choice = menu_choice(1, 2)
    print("-----------------------------------------------")
    print("1. AES 128/256")
    print("2. DES 64")
    print("3. BLOWFISH 128/256")
    print("4. CAST64")
    print("-----------------------------------------------")
    algo_choice = menu_choice(1, 4)
    if algo_choice == 1:
        print("-----------------------------------------------")
        print("1. AES128")
        print("2. AES256")
        print("-----------------------------------------------")
        key_size_choice = menu_choice(1, 2)
    if algo_choice == 3:
        print("-----------------------------------------------")
        print("1. BLOWFISH128")
        print("2. BLOWFISH256")
        print("-----------------------------------------------")
        key_size_choice = menu_choice(1, 2)
        print("-----------------------------------------------")
    if choice == 1:
        message = input("Veuillez saisir votre message: ")
        pwd = get_password()
        if algo_choice == 1 or algo_choice == 3:
            salt, encrypted = AVAILABLE_ALGO[algo_choice].encrypt(message, KEY_SIZE[key_size_choice], pwd)
            print("salt: ")
            print(salt)
            print("message encrypté: ")
            print(encrypted)
        elif algo_choice == 2 or algo_choice == 4:
            print("Le message crypté: ")
            salt, encrypted = AVAILABLE_ALGO[algo_choice].encrypt(message, pwd)
            print("salt: ")
            print(salt)
            print("message encrypté: ")
            print(encrypted)
    elif choice == 2:
        message = input("Veuillez saisir votre message chiffré: ")
        salt = input("Veuillez saisir votre salt: ")
        pwd = get_password()
        if algo_choice == 1 or algo_choice == 3:
            msg = AVAILABLE_ALGO[algo_choice].decrypt(message, KEY_SIZE[key_size_choice], salt, pwd)
            print("message decrypté: ")
            print(msg)
        elif algo_choice == 2 or algo_choice == 4:
            print("Le message crypté: ")
            msg = AVAILABLE_ALGO[algo_choice].decrypt(message, salt, pwd)
            print("message encrypté: ")
            print(msg)
    print("-----------------------------------------------")
    input("Tapez sur Entrée pour continuer...")


def asymmetric_menu():
    KEY_SIZE = {
        1: 1024,
        2: 2048,
        3: 3072
    }
    print("-----------------------------------------------")
    print("          Chiffrement Asymetrique RSA          ")
    print("-----------------------------------------------")
    print("-----------------------------------------------")
    print("1. Déchiffrement / Signature")
    print("2. Chiffrement / Verification signature")
    print("-----------------------------------------------")
    choice = menu_choice(1, 2)
    if choice == 1:
        print("-----------------------------------------------")
        print("1. Generer une paire de cle")
        print("2. Utiliser une cle privée existante")
        print("-----------------------------------------------")
        sub_choice = menu_choice(1, 2)
        if sub_choice == 1:
            print("-----------------------------------------------")
            print("La taille de clé")
            print("1. 1024")
            print("2. 2048")
            print("3. 3072")
            print("-----------------------------------------------")
            key_size_choice = menu_choice(1, 3)
            key_size_choice = KEY_SIZE[key_size_choice]
            path = input("Donner le chemin pour enregistrer les cles: ")
            pwd = get_password()
            if pwd == "":
                pwd = None
            private_str, public_str, private_key = rsa_utils.generate_keys(key_size_choice, pwd, path)
            if private_str:
                print("La clé public generé: ")
                print(public_str)
                print("La clé privée generé (!!Faites attention et cachez la!!): ")
                print(private_str)
            print("-----------------------------------------------")
            input("Tapez sur Entrée pour continuer...")
        elif sub_choice == 2:
            path = input("Donner le chemin pour la clé privée à utiliser: ")
            pwd = get_password()
            if pwd == "":
                pwd = None
            private_key = rsa_utils.read_private_key(path, pwd)
            if private_key is None:
                print("-----------------------------------------------")
                input("Tapez sur Entrée pour continuer...")
                return
        print("-----------------------------------------------")
        print("1. Decrypter un message")
        print("2. Signer un message")
        print("-----------------------------------------------")
        third_choice = menu_choice(1, 2)
        if third_choice == 1:
            encrypted = input("Veuillez saisir votre message crypté: ")
            print("Le message original: ")
            print(rsa_utils.decrypt(encrypted, private_key))
        elif third_choice == 2:
            message = input("Veuillez saisir votre message: ")
            print("Le message signé: ")
            print(rsa_utils.sign(message, private_key))
    elif choice == 2:
        path = input("Donner le chemin pour la clé public à utiliser: ")
        public_key = rsa_utils.read_public_key(path)
        if public_key is None:
            print("-----------------------------------------------")
            input("Tapez sur Entrée pour continuer...")
            return
        print("-----------------------------------------------")
        print("1. Crypter un message")
        print("2. Verifier la signature d'un message")
        print("-----------------------------------------------")
        sub_choice = menu_choice(1, 2)
        if sub_choice == 1:
            message = input("Veuillez saisir votre message: ")
            print("Le message crypté: ")
            print(rsa_utils.encrypt(message, public_key))
        elif sub_choice == 2:
            message = input("Veuillez saisir le message: ")
            signed = input("Veuillez saisir le message signé: ")
            if rsa_utils.verify(message, signed, public_key):
                print("le message signé contient le message donné et est bien signé par cette paire de clé")
            else:
                print("le message est erroné ou non signé par cette paire de clé")
    print("-----------------------------------------------")
    input("Tapez sur Entrée pour continuer...")


if __name__ == '__main__':
    try:
        while True:
            clear()
            print_title()
            choice = print_main_menu()
            if choice == 1:
                encoding_menu()
            elif choice == 2:
                hash_menu()
            elif choice == 3:
                brute_force_menu()
            elif choice == 4:
                symmetric_menu()
            elif choice == 5:
                asymmetric_menu()
            elif choice == 6:
                exit()
    except KeyboardInterrupt:
        print("See you soon.")
