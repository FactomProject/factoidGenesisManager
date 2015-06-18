# Factoid Genesis Manager

# This program generates random Factoid private keys and displays
# corresponding public keys.  It also allows for checking private keys.
# It creates Fs.... style private keys.  Wallets which support the
# Factoid Software Sale will be compatible with the keys generated
# by this program.

# This software is MIT licensed, Copyright 2015 Factom Foundation.

import sys
sys.path.append('libs')
import platform
import os
from mnemonic import Mnemonic
from bip32utils.BIP32Key import *
import ed25519djb as ed25519
import hashlib
import base58
import re
import sys

# the value 0x6478 specifies a private key for the base58 encoding
# it results in a string starting with "Fs" for Factoid Secret
factoid_secret_key_prefix = "6478"


def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).;

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")
def clear_screen():
    """
    this function gets rid of all the characters currently on the screen for readability
    """

    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')

def privkey_to_pubkey(privkey, advanced):
    """
    this function takes a 32 byte ed25519 private key and returns a 32 byte public key
    both values are binary encoded
    In this diagram: http://i.stack.imgur.com/5afWK.png
    from: http://crypto.stackexchange.com/questions/3596/is-it-possible-to-pick-your-ed25519-public-key
    takes in the k value and returns the A value
    The advanced parameter set to true displays technical internal data
    """
    pubkey = ed25519.publickey(privkey)
    if advanced == True:
        print "ed25519 Factoid public key: " + pubkey.encode('hex')
    return pubkey

def doublecheck_key_works(privkey, pubkey, advanced):
    """
    This function takes in a newly generated private and public key
    It signs a message and then validates the signature with the key.
    if the verification fails, it raises an exception and the script stops.
    """
    message = "message to sign"
    signature = ed25519.signature(message, privkey, pubkey)
    if advanced == True:
        print "test sig: " + signature.encode('hex')
    #signaturebad = signature[:1] + 'X' + signature[2:]
    #signaturebad2 = signature[:-2] + 'X' + signature[-1:]
    ed25519.checkvalid(signature, message, pubkey)
    if advanced == True:
        # if this script got this far, then the signature validated.
        print "signature good"

def pubkey_to_send(pubkey, advanced):
    """
    this function takes a 32 byte ed25519 public key in binary form and
    returns a string representing the public key in hex form
    It returns a string that breaks the value to send into 9 segments
    The string also has a checksum attached to it, so a typo is detectable.
    For example.  a binary pubkey passed like this :
    51477815b762e495e0f7deb01fb2969f2e15ba4615fa4a5aafc23ccf5c3c8bd2
    would return this string:


    Note, this function does not reutrn the FA...... style factoid address because the
    address scheme is not finalized.  The raw ed25519 key is what was committed to in the
    factoid sale, so this value will match the sale.

    The advanced parameter set to true displays technical internal data
    """
    pubkeyhash = hashlib.sha256(pubkey).digest()
    if advanced == True:
        print "SHA256 hash of pubkey: " + pubkeyhash.encode('hex')
    first4 = pubkeyhash[:4]
    if advanced == True:
        print "first 4 bytes of pubkey hash: " + first4.encode('hex')
    sendable = pubkey + first4
    if advanced == True:
        print "pubkey with checksum: " + sendable.encode('hex')
    num_digit_group=4
    display_string = ''
    for i in range(0, len(sendable), num_digit_group):
        display_string += sendable[i:i+num_digit_group].encode('hex')
        a = len(sendable)-num_digit_group
        if i < a:
            display_string += '-'
    return display_string

def private_key_to_human(private_key, advanced):
    """
    this function takes a 32 byte ed25519 private key in binary form and
    returns a string with a human readable private key according to this spec:
    https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md#factoid-private-keys
    For example.  a binary private key passed like this :
    12fab77add10bcabe1b62b3fe8b167e966e4beee38ccf0062fdd207b5906c841
    would return this string:
    Fs1Ts7PsKMwo4ftCYxQJ3rW4pLiRBXyGEjMrxtHycLu52aDgKGEy

    The advanced parameter set to true displays technical internal data
    """

    hex_seed = private_key.encode('hex')
    private_key_prefix = factoid_secret_key_prefix + hex_seed

    if advanced == True:
        print "Private key with prefix:   " + private_key_prefix

    digest = hashlib.sha256(hashlib.sha256(private_key_prefix.decode("hex")).digest()).digest()
    if advanced == True:
        print "Private key hash: " + digest.encode('hex')
    checksummed_private_key = private_key_prefix + digest[:4].encode('hex')
    if advanced == True:
        print "Private key with checksum: " + checksummed_private_key
    human_privkey =  base58.b58encode(checksummed_private_key.decode("hex"))
    if advanced == True:
        print "Human readable private key: " + human_privkey
    return human_privkey

def verify_written_wif(human_private_key, human_public_key, advanced):
    """
    this function prompts the user to correctly enter the private key and returns
    true if they correctly typed it
    It takes in two strings, the Fs... private key and the 9 segment pubkey

    The advanced parameter set to true displays technical internal data
    """
    while True:
        if advanced == False:
            clear_screen()
        print "Please write down this private key, starting with Fs: \n"
        print human_private_key
        print "\nThis is used to spend funds assigned to the public key starting with:"
        print human_public_key[:8]
        print "The Fs... number is the only way to recover Factoids after Factom launches."
        print "The private key also can be used to steal Factoids if exposed, so keep it secret"
        print "Capitalization matters."

        if advanced == False:
            raw_input("Press enter when done writing")
            clear_screen()
        written_wif = raw_input("Please type the private key you wrote, staring with Fs: ").strip()
        if written_wif == human_private_key:
            break
        else:
            if advanced == False:
                clear_screen()
            print "you typed: " + written_wif
            print "should be: " + human_private_key
            raw_input("please try again (press enter when ready or Ctrl+c to exit)")

def onlyB58chars(strg):
    """
    Returns false if the string passed in contains any invalid bitcoin base58 characters.
    """
    if re.match("^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$", strg):
        return True
    else:
        return False

def validate_private_key(human_private_key, advanced):
    """
    This function is intended to doublecheck a private key which was recorded earlier.
    It takes in the private key the user typed in.
    It displays the 9 segment public key which corresponds to that private key.
    It returns false if assorted errors are found.

    The advanced parameter set to true displays technical internal data
    """
    if onlyB58chars(human_private_key):
        decoded_key = base58.b58decode(human_private_key.strip())
    else:
        print "are you sure you typed the address correctly?"
        print "The address only can contain 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz but you typed: "
        print human_private_key
        return False

    if advanced == True:
        print "Hex decoded private key: " + decoded_key.encode('hex')
    if len(decoded_key) == 38:
        key_with_prefix = decoded_key[:34]
        if advanced == True:
            print "Private key with prefix: " + key_with_prefix.encode('hex')
        proper_checksum = hashlib.sha256(hashlib.sha256(key_with_prefix).digest()).digest()
        if advanced == True:
            print "Calculated checksum: " + proper_checksum.encode('hex')
        if proper_checksum[:4] == decoded_key[-4:]:
            print "The private key entered does not have any typos"
            privatekey = key_with_prefix[-32:]
            if advanced == True:
                print "raw ed25519 private key: " + privatekey.encode('hex')
            pubkey = privkey_to_pubkey(privatekey, advanced)
            doublecheck_key_works(privatekey, pubkey, advanced)
            human_pubkey = pubkey_to_send(pubkey, advanced)
            print "The public key to send to Factom is:"
            print human_pubkey
            return True
        else:
            print "are you sure you typed the address correctly?"
            print "you typed the checksum " + decoded_key[-4:].encode('hex') + " and calculated is " + proper_checksum[:4].encode('hex')
            return False
    else: # wrong key length
        print "are you sure you typed the address correctly?"
        print "expected decoded key length is 38 bytes but key decoded to length of " + str(len(decoded_key))
        return False

def verify_koinify_words(words):
    """
    This function checks to make sure there are multiple words and
    that the first word is in the english wordlist.
    Both of these errors would crash the Mnemonic library, so they should be checked before using it.
    The Mnemonic library checks for other errors.
    """
    if ' ' in words:
        wordchecker = Mnemonic('english')
        firstword = words.split(' ')[0]
        if firstword in wordchecker.wordlist:
            check = wordchecker.check(words)
            return check
        else:
            return False
    else:
        return False

def koinify_words_to_private_key(entered_words, advanced):
    """
    This function takes in a string with 12 words.
    It returns an ed25519 private key in binary format
    It uses the same algorithm used in the
    Koinify wallet during the factoid sale.

    The advanced parameter set to true displays technical internal data
    """
    seed = Mnemonic.to_seed(entered_words, '')
    rootkey = BIP32Key.fromEntropy(seed, public=False)
    factoidChildKey = rootkey.ChildKey(BIP32_HARDEN+7)
    last32 = factoidChildKey.ExtendedKey(private=True, encoded=False)[-32:]

    if advanced == True:
        print "seed derived from words: " + seed.encode('hex')
        print "BIP32 root key: " + rootkey.ExtendedKey(private=True, encoded=False).encode('hex')
        print "BIP32 root of Factoid chain key: " + factoidChildKey.ExtendedKey(private=True, encoded=False).encode('hex')
        print "Last 32 bytes, ed25519 private key: " + last32.encode('hex')
    return last32


def pubkey_to_opreturn(pubkey, advanced):
    """
    This function takes in binary 32 byte ed25519 public key
    It returns a hex encoded string displaying what would have been recorded
    in the bitcoin blockchain during the Factoid purchase.

    The advanced parameter set to true displays technical internal data
    """
    pubkeyHex = pubkey.encode('hex')
    opheader = "464143544f4d3030"
    opdata = opheader + pubkeyHex
    if advanced == True:
        print "data encoded in OP_RETURN is: " + opdata
    return opdata


def main():


    print "Factoid Genesis Manager v1.0"
    print "Press Ctrl+c to exit \n"

    if not testvectors():
        print "Something went terribly wrong.  Do you have all the files?"
        return False

    advanced = query_yes_no("Would you like to see technical details?","no")
    if advanced == False:
        clear_screen()
    print ""
    print "This program will both make and verify Factoid private and public keys."
    create_new = query_yes_no("Would you like to make a new Factoid private key?","yes")
    if create_new == True:
        private_key = os.urandom(32)
        if advanced == True:
            print "Random value is:               " + private_key.encode('hex')
        human_private_key = private_key_to_human(private_key, advanced)
        pubkey = privkey_to_pubkey(private_key, advanced)
        doublecheck_key_works(private_key, pubkey, advanced)
        pubkey_human = pubkey_to_send(pubkey, advanced)
        verify_written_wif(human_private_key, pubkey_human, advanced)
        print "Great!  Now send this 9 segment public key to Factom so that it can"
        print "be included in the Genesis block:\n"
        print pubkey_human
        raw_input("\npress enter when done")
    else:
        verify_factoid_private = query_yes_no("Would you like to verify an existing Factoid private key?","yes")
        if verify_factoid_private == True:
            while True:
                entered_private_key = raw_input("Please enter private key starting with Fs: ")
                if validate_private_key(entered_private_key, advanced):
                    raw_input("\npress enter when done")
                    break
                else:
                    raw_input("Ctrl+C to quit, Enter to try again")
        else:
            convert_koinify_words = query_yes_no("Would you like to convert the words from the Koinify wallet to a private key? ","yes")
            if convert_koinify_words == True:
                while True:
                    entered_words = raw_input("Please enter the 12 Koinify words: ")
                    if verify_koinify_words(entered_words.lower()):
                        private_key_from_koinify = koinify_words_to_private_key(entered_words.lower(), advanced)
                        human_privkey = private_key_to_human(private_key_from_koinify, advanced)
                        pubkey = privkey_to_pubkey(private_key_from_koinify, advanced)
                        doublecheck_key_works(private_key_from_koinify, pubkey, advanced)
                        pubkey_to_opreturn(pubkey, advanced)
                        print "Private key from the Koinify words: " + human_privkey
                        sendable_pubkey = pubkey_to_send(pubkey, advanced)
                        print "Corresponding to public key: " + sendable_pubkey
                        raw_input("\npress enter when done")
                        break
                    else:
                        print "Something is wrong with these entered words: "
                        print entered_words.lower()
                        print "All 12 words should have the same spelling as the english.txt file"
                        print "in the wordlist directory locally or on github"
                        raw_input("Ctrl+C to quit, Enter to try again")


def testvectors():
    """
    This function exercises the libraries and double checks that they are
    returning expected data.
    """
    print "Self Checking",
    print_dot()

    if "51477815b762e495e0f7deb01fb2969f2e15ba4615fa4a5aafc23ccf5c3c8bd2".decode('hex') != \
            privkey_to_pubkey("12fab77add10bcabe1b62b3fe8b167e966e4beee38ccf0062fdd207b5906c841".decode('hex'), False):
        return False
    print_dot()

    doublecheck_key_works("12fab77add10bcabe1b62b3fe8b167e966e4beee38ccf0062fdd207b5906c841".decode('hex'), \
            "51477815b762e495e0f7deb01fb2969f2e15ba4615fa4a5aafc23ccf5c3c8bd2".decode('hex'), False)
    print_dot()

    if "51477815-b762e495-e0f7deb0-1fb2969f-2e15ba46-15fa4a5a-afc23ccf-5c3c8bd2-6c4cf980" != \
            pubkey_to_send("51477815b762e495e0f7deb01fb2969f2e15ba4615fa4a5aafc23ccf5c3c8bd2".decode('hex'), False):
        return False
    print_dot()

    if "Fs1Ts7PsKMwo4ftCYxQJ3rW4pLiRBXyGEjMrxtHycLu52aDgKGEy" != \
            private_key_to_human("12fab77add10bcabe1b62b3fe8b167e966e4beee38ccf0062fdd207b5906c841".decode('hex'), False):
        return False
    print_dot()

    if not onlyB58chars("Xw1"):
        return False
    if onlyB58chars("$"):
        return False
    print_dot()

    if "4f4488c609552caf2c7a508108809518e9a1ab3ae6dc259a1e2e9989d053018d".decode('hex') != \
            hashlib.sha256(hashlib.sha256("647812fab77add10bcabe1b62b3fe8b167e966e4beee38ccf0062fdd207b5906c841" \
            .decode('hex')).digest()).digest():
        return False
    print_dot()

    if True != verify_koinify_words("legal winner thank year wave sausage worth useful legal winner thank yellow"):
        return False
    print_dot()
    if True == verify_koinify_words("legal winner thank year wave sausage worth useful legal winner thank thank"):
        return False
    print_dot()
    if "878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096" \
            .decode('hex') != Mnemonic.to_seed("legal winner thank year wave sausage worth useful legal winner thank yellow", ''):
        return False
    print_dot()
    if "0488ade4000000000000000000598b4595ea72802756519e65a797234231d7d4f13d650cb06db15957c2368b1b007e56ecf5943d79e1f5f87e11c768253d7f3fcf30ae71335611e366c578b4564e"\
            .decode('hex') != BIP32Key.fromEntropy("878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096"\
            .decode('hex'), public=False).ExtendedKey(private=True, encoded=False):
        return False
    print_dot()
    if "7999d61b8f5efc24b437244ff82b69ba474deeadbf144421f05d5b4b5ab20a8e".decode('hex') != \
            koinify_words_to_private_key("legal winner thank year wave sausage worth useful legal winner thank yellow", False):
        return False
    print("\n")
    # everything checks out ok
    return True

def print_dot():
    sys.stdout.write('.')
    sys.stdout.flush()

if "__main__" == __name__:
        main()

