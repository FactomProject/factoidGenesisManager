# Factoid Genesis Manager

# This program generates random Factoid private keys and displays
# corresponding public keys.  It also allows for checking private keys.
# It creates Fs.... style private keys.  Wallets which support the
# Factoid Software Sale will be compatible with the keys generated
# by this program.

# This software is MIT licensed, Copyright 2015 Factom Foundation.

import sys

import platform
import os
from mnemonic import Mnemonic
from bip32utils.BIP32Key import *
import ed25519
import hashlib
import base58
import re

# the value 0x6478 specifies a private key for the base58 encoding
# it results in a string starting with "Fs" for Factoid Secret
factoid_secret_key_prefix = "6478"


def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

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
        if platform.system() == 'Windows':
            os.system('cls')
        else:
            os.system('clear')

def seed_to_pubkey(random_seed, advanced):
    rootkey = BIP32Key.fromEntropy(random_seed, public=False)
    if advanced == True:
        print "BIP32 root key: " + rootkey.ExtendedKey(private=True, encoded=False).encode('hex')
    factoidChildKey = rootkey.ChildKey(BIP32_HARDEN+7)
    if advanced == True:
        print "BIP32 derived Factoid chain: " + factoidChildKey.ExtendedKey(private=True, encoded=False).encode('hex')
    last32 = factoidChildKey.ExtendedKey(private=True, encoded=False)[-32:]
    if advanced == True:
        print "Last 32 bytes from BIP32 ECDSA private key: " + last32.encode('hex')
        print "ed25519 Factoid private key: " + last32.encode('hex')
    pubkey = ed25519.publickey(last32)
    if advanced == True:
        print "ed25519 Factoid public key: " + pubkey.encode('hex')
    return pubkey

def privkey_to_pubkey(privkey, advanced):
    pubkey = ed25519.publickey(privkey)
    if advanced == True:
        print "ed25519 Factoid public key: " + pubkey.encode('hex')
    return pubkey

def pubkey_to_send(pubkey, advanced):
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

    while True:
        if advanced == False:
            clear_screen()
        print "Please write down this private key, starting with Fs: \n"
        print human_private_key
        print "\nThis is used to spend funds assigned to the public key starting with:"
        print human_public_key[:8]
        print "The Fs... number is the only way to recover Factoids after Factom launches."
        print "The private key also can be used to steal Factoids if exposed, so keep it secret."
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
    if re.match("^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$", strg):
        return True
    else:
        return False

def validate_private_key(human_private_key, advanced):
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

def verify_koinify_words(words, advanced):
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
    pubkeyHex = pubkey.encode('hex')
    opheader = "464143544f4d3030"
    opdata = opheader + pubkeyHex
    if advanced == True:
        print "data encoded in OP_RETURN is: " + opdata
    return opdata


def main():
    print "Factoid Genesis Manager v1.0"
    print "Press Ctrl+c to exit \n"
    advanced = query_yes_no("Would you like to see technical details?","yes")
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
        pubkey_human = pubkey_to_send(pubkey, advanced)
        verify_written_wif(human_private_key, pubkey_human, advanced)
        print "Great!  Now send this 9 segment public key to Factom so that it can be included in the Genesis block:\n"
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
                    if verify_koinify_words(entered_words.lower(), advanced):
                        private_key_from_koinify = koinify_words_to_private_key(entered_words.lower(), advanced)
                        human_privkey = private_key_to_human(private_key_from_koinify, advanced)
                        pubkey = privkey_to_pubkey(private_key_from_koinify, advanced)
                        pubkey_to_opreturn(pubkey, advanced)
                        print "Private key from the Koinify words: " + human_privkey
                        sendable_pubkey = pubkey_to_send(pubkey, advanced)
                        print "Corresponding to public key: " + sendable_pubkey
                        raw_input("\npress enter when done")
                        break
                    else:
                        print "Something is wrong with these entered words: "
                        print entered_words.lower()
                        print "All 12 words should have the same spelling as the english.txt file in the wordlist directory"
                        raw_input("Ctrl+C to quit, Enter to try again")

if "__main__" == __name__:
        main()

