Factoid Genesis Manager
==========

Current version is 1.0

This program is primarily for early contributors to generate private keys for Factoids.  It is a stand-alone program, so can be run on an offline computer.

#### Uses
- Generate an Fs... private key and corresponding 9 segment public key to send to Factom for inclusion in the genesis block.
- Validate an Fs... private key goes to a public key.
- Convert Koinify 12 words to an Fs... private key and 9 segment public key.



#### Instructions

First decide if you want to handle private keys on or off line. With an online computer, hackers or viruses can steal your Factoids when the system goes live, but is significantly easier to use.

### Online Usage

Browse to https://github.com/FactomProject/factoidGenesisManager and download the correct file for your operating system.

## Windows
1. Download [factoidGenesisManager.exe](https://github.com/FactomProject/factoidGenesisManager/blob/master/factoidGenesisManager.exe?raw=true)
2. Double click to run factoidGenesisManager.exe. A black terminal window will pop up with questions that can be answered with y or n. 
3. Write down the Fs... key that looks like `Fs1Ts7PsKMwo4exampLe3rW4pLiRBXyGEjMrxtHycLu52aDgKGEy`.  This is the key which will be imported into a future Factoid wallet.
4. Type the Fs... key back into the program to confirm you wrote it down correctly.
5. Send the 9 segment public key to Factom so it can be included in the Genesis block. The 9 segment public key looks like this: `51477815-b762e495-e0f7deb0-eeeeeeee-2e15ba46-15fa4a5a-afc23ccf-5c3c8bd2-6c4cf980`. Email the 9 segment key to brian@factom.org. You will recieve a phone call from someone in the Factom office confirming the first and last segments, so keep it handy before the launch of the genesis block.

![Windows Terminal](windows_example.png?raw=true)

## Mac and Linux

1. Download [factoidGenesisManager_mac_linux.zip](https://github.com/FactomProject/factoidGenesisManager/blob/master/factoidGenesisManager_mac_linux.zip?raw=true)
2. Unzip factoidGenesisManager_mac_linux.zip into the downloads folder.
  * Mac users can open the zip file. If you see `How To Run.txt` you have succeeded.
3. Open a Terminal window and browse to the factoidGenesisManager_mac_linux folder.
  * With a Mac, do this to accomplish step 3.
  * In the Spotlight, search for utilities.
  * Scroll through the results to the Folders section.
  * Double click on the Utilities folder.
  * Double click on Terminal to run it.
  * Type `cd downloads` and press return.
  * type `cd factoidGenesisManager_mac_linux` and press return.
4. Run the program by typing `python factoidGenesisManager.py` and pressing return. Follow the directions on screen.
5. Write down the Fs... key that looks like `Fs1Ts7PsKMwo4exampLe3rW4pLiRBXyGEjMrxtHycLu52aDgKGEy`.  This is the key which will be imported into a future Factoid wallet.
6. Type the Fs... key back into the program to confirm you wrote it down correctly.
7. Send the 9 segment public key to Factom so it can be included in the Genesis block. The 9 segment public key looks like this: `51477815-b762e495-e0f7deb0-eeeeeeee-2e15ba46-15fa4a5a-afc23ccf-5c3c8bd2-6c4cf980`. Email the 9 segment key to brian@factom.org. You will recieve a phone call from someone in the Factom office confirming the first and last segments, so keep it handy before the launch of the genesis block.

* If mac users have a broken terminal, you can try the zoc terminal alternative.

### Offline Usage
This is an example walk though to generate private keys on an offline computer.

1. Download [factoidGenesisManager_mac_linux.zip](https://github.com/FactomProject/factoidGenesisManager/blob/master/factoidGenesisManager_mac_linux.zip?raw=true) to a USB or SD card. from an online computer.
2. Burn a CD distribution of your favorite linux (xubuntu is a good choice)
3. From your offline computer, remove the hard drive, and all permanent storage media, like thumbdrives.
4. Boot the computer into linux. Disable any network or internet connections.
5. Insert the USB drive with factoidGenesisManager_mac_linux.zip into the computer.
6. Copy factoidGenesisManager_mac_linux.zip onto the home folder.
7. Remove the USB drive with factoidGenesisManager. All writable media should be removed from the computer at this point.
8. Open a terminal window and browse to the home directory `cd ~`.
9. Unzip factoidGenesisManager_mac_linux.zip into the folder factoidGenesisManager_mac_linux `unzip factoidGenesisManager_mac_linux.zip -d factoidGenesisManager_mac_linux`.
10. Browse to the factoidGenesisManager_mac_linux directory `cd factoidGenesisManager_mac_linux`.
11. Run the program `python factoidGenesisManager.py`.
12. Follow the directions to create a private and public key.  Write down the Private key.
13. Write down the 9 segment public key and reenter it onto an online computer.
14. Power off the computer to erase the private key from memory.
15. On an online computer, send the 9 segment public key to Factom so it can be included in the Genesis block. The 9 segment public key looks like this: `51477815-b762e495-e0f7deb0-eeeeeeee-2e15ba46-15fa4a5a-afc23ccf-5c3c8bd2-6c4cf980`. Email the 9 segment key to brian@factom.org. You will recieve a phone call from someone in the Factom office confirming the first and last segments, so keep it handy before the launch of the genesis block.

## Notes about keys

The Fs... keys stand for Factoid Secret.  The third letter will always be a 1, 2, or 3. Like bitcoin addresses, these key have checksums which prevent minor typos from losing funds.

The 9 segment public keys are the raw ed25519 public key.  The first 8 segments are the raw key, and the last segment is a SHA256 checksum of the key.  This will help prevent typos from losing Factoids.

Factoid *addresses* will start with FA... They are not generated by this tool, and will be displayed to you when you enter your private key into your future wallet.


