package main

import "fmt"
import "encoding/hex"
import "github.com/tyler-smith/go-bip32"
import "github.com/FactomProject/ed25519"
//import "crypto/sha512"

func main() {
	//words := "legal winner thank year wave sausage worth useful legal winner thank yellow"
	//no golang code to convert mnemonic to seed
	//instead used test vectors from https://github.com/FactomProject/FactomDocs/blob/master/token_sale/words_to_factoid_purchase.py
	
	seedvalue, _ := hex.DecodeString ("878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096")
	fmt.Printf("seed derived from words: %x\n", seedvalue)
	
	rootkey, _ := bip32.NewMasterKey(seedvalue)
	fmt.Printf("BIP32 root key: %x\n", rootkey.Serialize())

	factoidChildKey, _ := rootkey.NewChildKey(bip32.FirstHardenedChild+7)
	fmt.Printf("BIP32 root of Factoid chain key: %x\n", factoidChildKey.Serialize())

	last32 := factoidChildKey.Serialize()[46:78]
	fmt.Printf("Last 32 bytes, and privatekey: %x\n", last32)
	
	//expandedprivatekey := sha512.Sum512(last32)
	var combinedkeys [64]byte // := make([]byte, 64)
	copy(combinedkeys[:32], last32)
	
	pubkey := ed25519.GetPublicKey(&combinedkeys)
	fmt.Printf("The public key is: %x\n", pubkey[:32])
}


