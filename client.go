package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New(strings.ToTitle("An error occurred while generating a UUID: " + err.Error())))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type InviteInvite struct {
	InvUUID userlib.UUID
	InviteUUID userlib.UUID
	InvSymKey []byte
	InvMacKey []byte
}
type FileInvite struct {
	InviteUUID userlib.UUID
	FileUUID userlib.UUID
	FileSymKey []byte
	FileMacKey []byte
}
type File struct {
	FileUUID userlib.UUID
	Filename string
	FileOwner string
	InviteMap map[userlib.UUID]InviteInvite // inviteUUID : inv (to change FileInv using corresponding InvInv)
	UserMap map[string]userlib.UUID // username : inviteUUID
	HeadNode userlib.UUID
	TailNode userlib.UUID
}
type Node struct {
	NodeUUID userlib.UUID
	NextUUID userlib.UUID
	DataUUID userlib.UUID
}
type Data struct {
	DataUUID userlib.UUID
	Data []byte
}
type User struct {
	UserUUID userlib.UUID
	Username string
	Password string
	RSAKEY userlib.PKEDecKey
	SIGNKEY userlib.DSSignKey
	AccessList map[userlib.UUID]InviteInvite // invUUID : inv

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).


}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {

	/// error if: username already exists
	/// error if: username is empty

	if (len(username) == 0) {
		return nil, errors.New("username is empty")
	}

	// init user struct, store in dataStore
	salt := userlib.Hash([]byte(username))
	saltyHash := userlib.Hash([]byte(password + string(salt)))
	userUUID, err := uuid.FromBytes(saltyHash[:16])
	if (err != nil) {
		return nil, err
	}

	_, userExists := userlib.DatastoreGet(userUUID)
	if (userExists) {
		return nil, errors.New("username already exists")
	}

	// store public rsa key in keystore - (username + '/rsa') : key
	// store public ver key in keystore - (username + '/sign') : key
	rsaKey, decKey, err := userlib.PKEKeyGen()
	if (err != nil) {
		return nil, err
	}
	signKey, verifyKey, err := userlib.DSKeyGen()
	if (err != nil) {
		return nil, err
	}
	err = userlib.KeystoreSet(username + "/rsa", rsaKey)
	if (err != nil) {
		return nil, err
	}
	err = userlib.KeystoreSet(username + "/sign", verifyKey)
	if (err != nil) {
		return nil, err
	}
	// if either keyGen or keystoreSet fails

	var userdata User
	userdata.UserUUID = userUUID
	userdata.Username = username
	userdata.Password = password
	userdata.RSAKEY = decKey
	userdata.SIGNKEY = signKey
	userdata.AccessList = make(map[userlib.UUID]InviteInvite)

	err = StoreUser(&userdata)
	if (err != nil) {
		return nil, err
	}
	// if any StoreUser functions fail

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	/// error if: no initialized user for username
	/// error if: user credentials are invalid
	/// error if: user struct cannot be obtained due to malicious actions or lost integrity

	salt := userlib.Hash([]byte(username))
	saltyHash := userlib.Hash([]byte(password + string(salt)))
	userUUID, err := uuid.FromBytes(saltyHash[:16])
	if (err != nil) {
		return nil, err // if can't calculate UUID from saltyHash
	}

	// use first 16 bytes as SymEncKey; last 16 bytes as MacKey
	key := userlib.Argon2Key(userlib.Hash([]byte(password)), salt, 32)

	userStore, userOk := userlib.DatastoreGet(userUUID)
	if (!userOk) {
		return nil, errors.New("no initialized user for username")
	}
	if(len(userStore) < 64){
		return nil, errors.New("user data compromised")
	}
	compareMac := userStore[len(userStore)-64:]
	userCipher := userStore[:len(userStore)-64]

	userHmac, err := userlib.HMACEval(key[16:], userCipher)
	if (err != nil) {
		return nil, err // if can't calculate HMAC
	}
	validHmac := userlib.HMACEqual(compareMac, userHmac)
	if (!validHmac) {
		return nil, errors.New("integrity of user cannot be verified")
	}

	var userdata User
	userPlain := userlib.SymDec(key[:16], userCipher)
	err = json.Unmarshal(userPlain, &userdata)
	if (err != nil) {
		return nil, err // if marshal went wrong
	}

	if (userdata.Username != username || userdata.Password != password) {
		return nil, errors.New("user credentials are invalid")
	}

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	/// error if: write cannot occur due to malicious action

	// sync userdata with dataStore for multiple user instances
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if (err != nil) {
		return err
	}

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if (err != nil) {
		return err
	}
	// _, loadErr := userlib.DatastoreGet(storageKey)
	// if(loadErr){
	// 	return errors.New(filename + " file alr exists")
	// }

	var file File
	var inv InviteInvite
	var invite FileInvite
	inv, fileExists := userdata.AccessList[storageKey]

	// if file does not exist: create ownerInvite, init fileHeader/inv/invite
	if (!fileExists) {
		inv.InvUUID = storageKey
		inv.InviteUUID = uuid.New()
		inv.InvSymKey = userlib.RandomBytes(16)
		inv.InvMacKey = userlib.RandomBytes(16)

		// store inv within user's accessList
		userdata.AccessList[inv.InvUUID] = inv
		err = StoreUser(userdata)
		if (err != nil) {
			return err
		}

		invite.InviteUUID = inv.InviteUUID
		invite.FileUUID = uuid.New()
		invite.FileSymKey = userlib.RandomBytes(16)
		invite.FileMacKey = userlib.RandomBytes(16)

		file.FileUUID = invite.FileUUID
		file.Filename = filename
		file.FileOwner = userdata.Username
		file.InviteMap = make(map[userlib.UUID]InviteInvite)
		file.InviteMap[invite.InviteUUID] = inv
		file.UserMap = make(map[string]userlib.UUID)
		file.UserMap[userdata.Username] = invite.InviteUUID
	} else {
		err = GetInvite(&inv, &invite)
		if (err != nil) {
			return err
		}
		err = GetFileHeader(&invite, &file)
		if (err != nil) {
			return err
		}

		// error if: invalid invite used to perform action
		_, validInvite := file.InviteMap[inv.InviteUUID]
		if (!validInvite) {
			return errors.New("invitation invalid, fetched garbage")
		}
	}

	// if file exists: overwrite; need to update node/data
	var data Data
	data.DataUUID = uuid.New()
	data.Data = content

	var node Node
	node.NodeUUID = uuid.New()
	node.NextUUID = uuid.Nil
	node.DataUUID = data.DataUUID

	file.HeadNode	= node.NodeUUID
	file.TailNode = node.NodeUUID

	err = StoreInvite(&inv, &invite)
	if (err != nil) {
		return err
	}
	err = StoreFileData(&invite, &data)
	if (err != nil) {
		return err
	}
	err = StoreFileNode(&invite, &node)
	if (err != nil) {
		return err
	}
	err = StoreFileHeader(&invite, &file)
	if (err != nil) {
		return err
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	/// error if: filename is not in personal file namespace of caller
	/// error if: appending cannot succeed due to malicious actions

	// sync userdata with dataStore for multiple user instances
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if (err != nil) {
		return err
	}

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if (err != nil) {
		return err
	}

	inv, invOk := userdata.AccessList[storageKey]
	if (!invOk) {
		return errors.New("filename not in personal file namespace")
	}

	var invite FileInvite
	err = GetInvite(&inv, &invite)
	if (err != nil) {
		return err
	}

	var file File
	err = GetFileHeader(&invite, &file)
	if (err != nil) {
		return err
	}

	// error if: invalid invite used to perform action
	_, validInvite := file.InviteMap[inv.InviteUUID]
	if (!validInvite) {
		return errors.New("invitation invalid, fetched garbage")
	}

	// create new node/data
	var newData Data
	newData.DataUUID = uuid.New()
	newData.Data = content

	var newNode Node
	newNode.NodeUUID = uuid.New()
	newNode.NextUUID = uuid.Nil
	newNode.DataUUID = newData.DataUUID

	// find tailNode to append to
	var tailNode Node
	err = GetFileNode(&invite, &tailNode, file.TailNode)
	if (err != nil) {
		return err
	}

	// change tailNode.next, file.tailNode
	tailNode.NextUUID = newNode.NodeUUID
	file.TailNode = newNode.NodeUUID

	err = StoreFileData(&invite, &newData)
	if (err != nil) {
		return err
	}
	err = StoreFileNode(&invite, &newNode)
	if (err != nil) {
		return err
	}
	err = StoreFileNode(&invite, &tailNode)
	if (err != nil) {
		return err
	}
	err = StoreFileHeader(&invite, &file)
	if (err != nil) {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (fileContent []byte, err error) {

	/// error if: filename is not in personal file namespace of caller
	/// error if: integrity of content cannot be verified
	/// error if: loading file cannot succeed due to any other malicious action

	// sync userdata with dataStore for multiple user instances
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if (err != nil) {
		return nil, err
	}

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if (err != nil) {
		return nil, err
	}

	// fetch invite from userdata
	inv, invOk := userdata.AccessList[storageKey]
	if (!invOk) {
		return nil, errors.New("filename is not in personal file namespace")
	}

	var invite FileInvite
	err = GetInvite(&inv, &invite)
	if (err != nil) {
		return nil, err
	}

	var file File
	err = GetFileHeader(&invite, &file)
	if (err != nil) {
		return nil, err
	}

	// error if: invalid invite used to perform action
	_, validInvite := file.InviteMap[inv.InviteUUID]
	if (!validInvite) {
		return nil, errors.New("invitation invalid, fetched garbage")
	}

	var content []byte
	var node Node
	var data Data

	nodeUUID := file.HeadNode
	// for each node in file: append data to returned content
	for (nodeUUID != uuid.Nil) {
		err = GetFileNode(&invite, &node, nodeUUID)
		if (err != nil) {
			return nil, err
		}
		err = GetFileData(&invite, &data, node.DataUUID)
		if (err != nil) {
			return nil, err
		}

		content = append(content, data.Data...)
		nodeUUID = node.NextUUID
	}

	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	/// error if: filename is not in personal file namespace of caller
	/// error if: recipientUsername does not exist
	/// error if: sharing cannot complete due ot any malicious action

	// sync userdata with dataStore for multiple user instances
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if (err != nil) {
		return uuid.Nil, err
	}

	// recipient will not have name for shared file in their personal namespace until accept
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return uuid.Nil, err
	}

	// find file and create invite corresponding to the FileUUID
	ownerInv, ownerOk := userdata.AccessList[storageKey]
	if (!ownerOk) {
		return uuid.Nil, errors.New("filename is not in personal file namespace")
	}

	var ownerInvite FileInvite
	err = GetInvite(&ownerInv, &ownerInvite)
	if (err != nil) {
		return uuid.Nil, err
	}

	var file File
	err = GetFileHeader(&ownerInvite, &file)
	if (err != nil) {
		return uuid.Nil, err
	}


	var guestInv InviteInvite
	var guestInvite FileInvite
	// check if user is fileOwner, else share own invite
	if (userdata.Username == file.FileOwner) {
		guestInvite.InviteUUID = uuid.New() // new invite object for recipUser
		guestInv.InvSymKey = userlib.RandomBytes(16)
		guestInv.InvMacKey = userlib.RandomBytes(16)
	} else {
		guestInvite.InviteUUID = ownerInvite.InviteUUID
		guestInv.InvSymKey = ownerInv.InvSymKey
		guestInv.InvMacKey = ownerInv.InvMacKey
	}
	guestInvite.FileUUID = ownerInvite.FileUUID
	guestInvite.FileSymKey = ownerInvite.FileSymKey
	guestInvite.FileMacKey = ownerInvite.FileMacKey

	// create guestInv to store into file before sending, store guestInvite on dataStore
	guestInv.InvUUID = uuid.Nil // nil on file, will be storageKey in user
	guestInv.InviteUUID = guestInvite.InviteUUID

	err = StoreInvite(&guestInv, &guestInvite)
	if (err != nil) {
		return uuid.Nil, err
	}

	// add owner shared guestInv to file access list; only re-encrypt fileHeader
	if (userdata.Username == file.FileOwner) {
		file.InviteMap[guestInvite.InviteUUID] = guestInv
		file.UserMap[recipientUsername] = guestInvite.InviteUUID
		err = StoreFileHeader(&ownerInvite, &file)
		if (err != nil) {
			return uuid.Nil, err
		}
	}

	// encrypt and mac inv to send
	// custom []byte encoding function to reduce size for PKEEnc (< 126 bytes)
	invPlain, err := InvMarshal(&guestInv)
	if (err != nil) {
		return uuid.Nil, err
	}

	// encrypt using public RSA key from Keystore
	recipEncKey, recipOk := userlib.KeystoreGet(recipientUsername + "/rsa")
	if (!recipOk) {
		 return uuid.Nil, errors.New("recipientKey could not be found / recipientUsername does not exist")
	}
	invCipher, err := userlib.PKEEnc(recipEncKey, invPlain)
	if (err != nil) {
		return uuid.Nil, err
	}

 	// sign using private DS key from userdata
	sign, err := userlib.DSSign(userdata.SIGNKEY, invCipher)
	if (err != nil) {
		return uuid.Nil, err
	}

	invPacket := append(invCipher, sign...)
	invPacketUUID := uuid.New()
	userlib.DatastoreSet(invPacketUUID, invPacket)

	return invPacketUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	/// error if: caller already has file with given filename in personal file namespace
	/// error if: caller cannot verify that secure file share invitation was created by senderUsername
	/// error if: invitation is no longer valid due to revocation (check if inviteUUID in filespace)
	/// error if: caller unable to verify integrity of file share invitation

	// sync userdata with dataStore for multiple user instances
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if (err != nil) {
		return err
	}

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}

	// check if filename already exists in personal file namespace
	_, exists := userdata.AccessList[storageKey]
	if (exists) {
		return errors.New("filename already exists in user file namespace")
	}

	// verify invPacket using public DS key from Keystore
	senderVerifyKey, senderOk := userlib.KeystoreGet(senderUsername + "/sign")
	if (!senderOk) {
		return errors.New("senderKey could not be found")
	}
	signedPacket, packetOk := userlib.DatastoreGet(invitationPtr)
	if (!packetOk) {
		return errors.New("invPacket could not be found")
	}
	if(len(signedPacket) < 256){
		return errors.New("packet modified?")
	}
	invCipher, signature := signedPacket[:len(signedPacket)-256], signedPacket[len(signedPacket)-256:]
	err = userlib.DSVerify(senderVerifyKey, invCipher, signature)
	if (err != nil) {
		return err // cannot verify inv authenticity/integrity
	}

	// decrypt using private RSA key from userdata
	invPlain, err := userlib.PKEDec(userdata.RSAKEY, invCipher)
	if (err != nil) {
		return err
	}

	var userInv InviteInvite
	err = InvUnmarshal(invPlain, &userInv)
	if (err != nil) {
		return err
	}

	var userInvite FileInvite
	err = GetInvite(&userInv, &userInvite)
	if (err != nil) {
		return err
	}

	// check if userInvite is in file access list; only need to fetch file header
	var file File
	err = GetFileHeader(&userInvite, &file) // if incorrect invite/decryption, file will be garbage anyways
	if (err != nil) {
		return err
	}
	// if(file.Filename != filename){
	// 	return errors.New("not the right file?")
	// }
	_, inviteAllowed := file.InviteMap[userInv.InviteUUID]
	if (!inviteAllowed) {
		return errors.New("invitation invalid")
	}

	// add userInv to userdata AND update fileInviteList
	userInv.InvUUID = storageKey
	userdata.AccessList[userInv.InvUUID] = userInv
	err = StoreUser(userdata)
	if (err != nil) {
		return err
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	/// error if: filename is not in personal file namespace of caller
	/// error if: filename is not currently shared with recipientUsername
	/// error if: revocation cannot complete due ot malicious action

	// sync userdata with dataStore for multiple user instances
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if (err != nil) {
		return err
	}
	if (userdata.Username == recipientUsername){
		return errors.New("trying to revoke from yourself???")
	}

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}

	// decode invite and error checking
	ownerInv, invOk := userdata.AccessList[storageKey]
	if (!invOk) {
		return errors.New("filename is not in personal file namespace")
	}

	var ownerInvite FileInvite
	err = GetInvite(&ownerInv, &ownerInvite)
	if (err != nil) {
		return err
	}

	var file File
	err = GetFileHeader(&ownerInvite, &file)
	if (err != nil) {
		return err
	}

	// load data to store in
	content, err := userdata.LoadFile(filename)
	if (err != nil) {
		return err
	}

	inviteUUID, inviteOk := file.UserMap[recipientUsername] // only need to consider direct shares by owner
	if (!inviteOk) {
		return errors.New("file is not currently shared with recipient")
	}

	// update file header: remove inviteUUID from file access list
	delete(file.InviteMap, inviteUUID) // inviteUUID : inv
	delete(file.UserMap, recipientUsername) // name : inviteUUID
	// delete deprecated file and invite from datastore
	userlib.DatastoreDelete(file.FileUUID)
	userlib.DatastoreDelete(inviteUUID)

	// create new file structs; create new file
	var data Data
	data.DataUUID = uuid.New()
	data.Data = content

	var node Node
	node.NodeUUID = uuid.New()
	node.NextUUID = uuid.Nil
	node.DataUUID = data.DataUUID

	file.FileUUID = uuid.New()
	file.HeadNode	= node.NodeUUID
	file.TailNode = node.NodeUUID

	ownerInvite.FileUUID = file.FileUUID;
	ownerInvite.FileSymKey = userlib.RandomBytes(16);
	ownerInvite.FileMacKey = userlib.RandomBytes(16);

	// refresh remaining invites with new keys and fileUUID
	var invite FileInvite
	for _, inv := range file.InviteMap {
		err := GetInvite(&inv, &invite)
		if (err != nil) {
			return err
		}

		invite.FileUUID = ownerInvite.FileUUID
		invite.FileSymKey = ownerInvite.FileSymKey
		invite.FileMacKey = ownerInvite.FileMacKey
		err = StoreInvite(&inv, &invite)
		if (err != nil) {
			return err
		}
	}
	delete(userdata.AccessList, storageKey)

	err = StoreFileData(&ownerInvite, &data)
	if (err != nil) {
		return err
	}
	err = StoreFileNode(&ownerInvite, &node)
	if (err != nil) {
		return err
	}
	err = StoreFileHeader(&ownerInvite, &file)
	if (err != nil) {
		return err
	}

	return nil
}

// Helper fncs

func StoreUser(userdata *User) (err error) {
	userPlain, err := json.Marshal(userdata)
	if (err != nil) {
		return err
	}

	nonce := userlib.RandomBytes(16)
	salt := userlib.Hash([]byte(userdata.Username))
	key := userlib.Argon2Key(userlib.Hash([]byte(userdata.Password)), salt, 32)
	userCipher := userlib.SymEnc(key[:16], nonce, userPlain)

	userHmac, err := userlib.HMACEval(key[16:], userCipher)
	if (err != nil) {
		return err
	}

	userStore := append(userCipher, userHmac...)
	userlib.DatastoreSet(userdata.UserUUID, userStore) // datastoreSet does not return anything

	return nil
}

func InvMarshal(inv *InviteInvite) (content []byte, err error) {
	// use same function signature as Marshal/Unmarshal for consistency
	var ret []byte
	// userlib.DebugMsg("InviteUUID length: %d", len(invite.InviteUUID.MarshalBinary())) = 16
	// userlib.DebugMsg("FileUUID length: %d", len(invite.FileUUID.MarshalBinary())) = 16
	// userlib.DebugMsg("FileSymKey length: %d", len(invite.FileSymKey)) = 16
	// userlib.DebugMsg("FileMacKey length: %d", len(invite.FileMacKey)) = 16
	invID, _ := inv.InvUUID.MarshalBinary()
	inviteID, _ := inv.InviteUUID.MarshalBinary()
	ret = invID
	ret = append(ret, inviteID...)
	ret = append(ret, inv.InvSymKey...)
	ret = append(ret, inv.InvMacKey...)

	return ret, nil
}

func InvUnmarshal(content []byte, inv *InviteInvite) (err error) {
	// use same function signature as Marshal/Unmarshal for consistency
	inv.InvUUID, _ = uuid.FromBytes(content[:16])
	inv.InviteUUID, _ = uuid.FromBytes(content[16:32])
	inv.InvSymKey = content[32:48]
	inv.InvMacKey = content[48:]

	return nil
}

// Go does not allow function overloading (most likely for security?)
func GetInvite(inv *InviteInvite, invitePtr *FileInvite) (err error) {

	invite, inviteOk := userlib.DatastoreGet(inv.InviteUUID)
	if (!inviteOk) {
		return errors.New("invite could not be found")
	}

	compareMac := invite[len(invite)-64:]
	inviteCipher := invite[:len(invite)-64]

	inviteHmac, err := userlib.HMACEval(inv.InvMacKey, inviteCipher)
	if (err != nil) {
		return err
	}
	validHmac := userlib.HMACEqual(compareMac, inviteHmac)
	if (!validHmac) {
		return errors.New("integrity of invite cannot be verified")
	}

	invitePlain := userlib.SymDec(inv.InvSymKey, inviteCipher)
	err = json.Unmarshal(invitePlain, invitePtr)
	if (err != nil) {
		return err
	}

	return nil
}

func GetFileHeader(invite *FileInvite, filePtr *File) (err error) {

	file, fileOk := userlib.DatastoreGet(invite.FileUUID)
	if (!fileOk) {
		return errors.New("file header could not be found")
	}

	compareMac := file[len(file)-64:]
	fileCipher := file[:len(file)-64]

	fileHmac, err := userlib.HMACEval(invite.FileMacKey, fileCipher)
	if (err != nil) {
		return err
	}
	validHmac := userlib.HMACEqual(compareMac, fileHmac)
	if (!validHmac) {
		return errors.New("integrity of file header cannot be verified")
	}

	filePlain := userlib.SymDec(invite.FileSymKey, fileCipher)
	err = json.Unmarshal(filePlain, filePtr)
	if (err != nil) {
		return err
	}

	return nil
}

func GetFileNode(invite *FileInvite, nodePtr *Node, nodeUUID userlib.UUID) (err error) {

	node, nodeOk := userlib.DatastoreGet(nodeUUID)
	if (!nodeOk) {
		return errors.New("node could not be found")
	}

	compareMac := node[len(node)-64:]
	nodeCipher := node[:len(node)-64]

	nodeHmac, err := userlib.HMACEval(invite.FileMacKey, nodeCipher)
	if (err != nil) {
		return err
	}
	validHmac := userlib.HMACEqual(compareMac, nodeHmac)
	if (!validHmac) {
		return errors.New("integrity of node cannot be verified")
	}

	nodePlain := userlib.SymDec(invite.FileSymKey, nodeCipher)
	err = json.Unmarshal(nodePlain, nodePtr)
	if (err != nil) {
		return err
	}

	return nil
}

func GetFileData(invite *FileInvite, dataPtr *Data, dataUUID userlib.UUID) (err error) {

	data, dataOk := userlib.DatastoreGet(dataUUID)
	if (!dataOk) {
		return errors.New("data could not be found")
	}

	compareMac := data[len(data)-64:]
	dataCipher := data[:len(data)-64]

	dataHmac, err := userlib.HMACEval(invite.FileMacKey, dataCipher)
	if (err != nil) {
		return err
	}
	validHmac := userlib.HMACEqual(compareMac, dataHmac)
	if (!validHmac) {
		return errors.New("integrity of data cannot be verified")
	}

	dataPlain := userlib.SymDec(invite.FileSymKey, dataCipher)
	err = json.Unmarshal(dataPlain, dataPtr)
	if (err != nil) {
		return err
	}

	return nil
}

func StoreInvite(inv *InviteInvite, invitePtr *FileInvite) (err error) {

	invitePlain, err := json.Marshal(invitePtr)
	if (err != nil) {
		return err
	}

	nonce := userlib.RandomBytes(16)
	inviteCipher := userlib.SymEnc(inv.InvSymKey, nonce, invitePlain)
	inviteHmac, err := userlib.HMACEval(inv.InvMacKey, inviteCipher)
	if (err != nil) {
		return err
	}

	inviteStore := append(inviteCipher, inviteHmac...)
	userlib.DatastoreSet(invitePtr.InviteUUID, inviteStore)

	return nil
}

func StoreFileHeader(invite *FileInvite, filePtr *File) (err error) {

	filePlain, err := json.Marshal(filePtr)
	if (err != nil) {
		return err
	}

	nonce := userlib.RandomBytes(16)
	fileCipher := userlib.SymEnc(invite.FileSymKey, nonce, filePlain)
	fileHmac, err := userlib.HMACEval(invite.FileMacKey, fileCipher)
	if (err != nil) {
		return err
	}

	fileStore := append(fileCipher, fileHmac...)
	userlib.DatastoreSet(filePtr.FileUUID, fileStore)

	return nil
}

func StoreFileNode(invite *FileInvite, nodePtr *Node) (err error) {

	nodePlain, err := json.Marshal(nodePtr)
	if (err != nil) {
		return err
	}

	nonce := userlib.RandomBytes(16)
	nodeCipher := userlib.SymEnc(invite.FileSymKey, nonce, nodePlain)
	nodeHmac, err := userlib.HMACEval(invite.FileMacKey, nodeCipher)
	if (err != nil) {
		return err
	}

	nodeStore := append(nodeCipher, nodeHmac...)
	userlib.DatastoreSet(nodePtr.NodeUUID, nodeStore)

	return nil
}

func StoreFileData(invite *FileInvite, dataPtr *Data) (err error) {

	dataPlain, err := json.Marshal(dataPtr)
	if (err != nil) {
		return err
	}

	nonce := userlib.RandomBytes(16)
	dataCipher := userlib.SymEnc(invite.FileSymKey, nonce, dataPlain)
	dataHmac, err := userlib.HMACEval(invite.FileMacKey, dataCipher)
	if (err != nil) {
		return err
	}

	dataStore := append(dataCipher, dataHmac...)
	userlib.DatastoreSet(dataPtr.DataUUID, dataStore)

	return nil
}
