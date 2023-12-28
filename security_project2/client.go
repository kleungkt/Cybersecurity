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

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() (err error) {

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
		return fmt.Errorf("An error occurred while generating a UUID: " + err.Error())
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
		//panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random Private/public keypair.
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
		//panic(err)
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
	_ = fmt.Sprintf("%s_%d", "File", 1)
	return err
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username              string
	Salt                  []byte
	UserID                uuid.UUID
	RootKey               []byte //TODO: still can't figure out the usage of RootKey
	PrivKeyFileEnc        userlib.PKEDecKey
	PrivKeyFileAppendEnc  userlib.PKEDecKey
	PrivKeyInviteEnc      userlib.PKEDecKey
	PrivKeyUserSign       userlib.DSSignKey
	PrivKeyFileSign       userlib.DSSignKey
	PrivKeyFileAppendSign userlib.DSSignKey
	PrivKeyInviteSign     userlib.DSSignKey
	PrivSymKeyEnc         userlib.DSSignKey
	FilesCreated          map[string]uuid.UUID //key: Filename, value: FileID
	FilesSharedToMe       map[string]uuid.UUID //key: Filename, value: FileID
	UsersSharedToMe       map[string]uuid.UUID //key: Filename, value: UserID
	HmacUser              []byte
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "Private" variable (e.g. one that
	// begins with a lowercase letter).
}
type UserPackage struct {
	UserJSON []byte
	Salt     []byte
	UserSign []byte
}
type File struct {
	Content   []byte
	CreatorID uuid.UUID
	FileID    uuid.UUID
}

type FilePackage struct {
	FileJSON []byte
	FileSign []byte
}

type FileAppend struct {
	MFID uuid.UUID //MainFileID
	AP   []uuid.UUID
	FAID uuid.UUID //FileAppendID
	//CreatorID    uuid.UUID
}
type FileAppendPackage struct {
	FileAppendJSON []byte
	FileAppendSign []byte
}
type Invitation struct {
	CreatorID           uuid.UUID
	CreatorName         string
	AcceptorID          uuid.UUID
	FileID              uuid.UUID
	InvitationID        uuid.UUID
	IsAccepted          bool //not encrypted
	IsRevoked           bool //not encrypted
	InvitationParentPtr uuid.UUID
}

type InvitationPackage struct {
	InvitationJSON []byte
	InvitationSign [][]byte
	CreatorIDByte  []byte
}
type KeyList struct {
	List      [][]byte
	KeyListID uuid.UUID
}

// HELPER functions:
func getUserFromStoreByRootKey(UserID uuid.UUID, RootKey []byte) (userRet *User, err error) {
	var userPackage UserPackage
	userPackageJSON, ok := userlib.DatastoreGet(UserID)
	if ok == false {
		return nil, fmt.Errorf(("Cannot find user" + err.Error()))
	}
	err = json.Unmarshal(userPackageJSON, &userPackage)

	if err != nil {
		return nil, fmt.Errorf(("Error occurred when deserializing userPackage" + err.Error()))
	}
	pubKeyUserSign, ok := userlib.KeystoreGet(UserID.String() + "UserSign")
	if ok == false {
		return nil, fmt.Errorf("Error occurred when getting UserSign key from KeyStore")
	}
	err = userlib.DSVerify(pubKeyUserSign, userPackage.UserJSON, userPackage.UserSign)
	if err != nil {
		return nil, fmt.Errorf("Cannot verify user package, it may have been tampered with: " + err.Error())
	}
	var plaintext = userlib.SymDec(RootKey, userPackage.UserJSON)
	var user User
	err = json.Unmarshal(plaintext, &user)
	if err != nil {
		return nil, fmt.Errorf("Cannot decrypt user: " + err.Error())
	}
	return &user, err

}
func getUserFromStore(UserID uuid.UUID, Password string) (userRet *User, found bool, err error) {

	var userPackage UserPackage
	userPackageJSON, ok := userlib.DatastoreGet(UserID)
	if ok == false {
		return nil, false, nil
	}
	err = json.Unmarshal(userPackageJSON, &userPackage)

	if err != nil {
		return nil, false, fmt.Errorf("Error occurred when deserializing userPackage" + err.Error())
	}
	pubKeyUserSign, ok := userlib.KeystoreGet(UserID.String() + "UserSign")
	if ok == false {
		return nil, false, fmt.Errorf("Error occurred when getting UserSign key from KeyStore")
	}
	err = userlib.DSVerify(pubKeyUserSign, userPackage.UserJSON, userPackage.UserSign)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot verify user package, it may have been tampered with: " + err.Error())
	}
	var localRootKey = userlib.Argon2Key([]byte(Password), userPackage.Salt, 16)
	var plaintext = userlib.SymDec(localRootKey, userPackage.UserJSON)
	var user User
	err = json.Unmarshal(plaintext, &user)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot decrypt user: " + err.Error())
	}
	return &user, true, nil

}

func sendUserToStore(UserID uuid.UUID, userdataptr *User) (err error) {
	marshal, err := json.Marshal(*userdataptr)
	if err != nil {
		return fmt.Errorf("An error occurred while transforming User to JSON: " + err.Error())
	}
	cipher := userlib.SymEnc(userdataptr.RootKey, userdataptr.Salt, marshal)

	var userPackage UserPackage
	userPackage.UserJSON = cipher
	userPackage.UserSign, err = userlib.DSSign(userdataptr.PrivKeyUserSign, cipher)
	userPackage.Salt = userdataptr.Salt
	marshal, err = json.Marshal(userPackage)
	if err != nil {
		return fmt.Errorf("An error occurred while transforming UserPackage to JSON: " + err.Error())
	}
	userlib.DatastoreSet(UserID, marshal)
	return err
}
func (userdata *User) getKeyFromStore(keyListID uuid.UUID) (validKeyRet []byte, err error) {
	KeyListJSON, found := userlib.DatastoreGet(keyListID)
	if found == false {
		return nil, fmt.Errorf("Cannot find the keyList with ID: %v", keyListID)
	}
	var keyList KeyList
	err = json.Unmarshal(KeyListJSON, &keyList)
	if err != nil {
		return nil, fmt.Errorf("Error occurred when unmarshaling keylistJSON" + err.Error())
	}
	var plainKey []byte
	for _, k := range keyList.List {
		plainKey, err = userlib.PKEDec(userdata.PrivSymKeyEnc, k)
		if err != nil {
			continue
		}
	}
	if len(plainKey) == 0 {
		return nil, fmt.Errorf("Cannot find a valid key for this user")
	}
	return plainKey, err
}
func (userdata *User) sendKeyToStore(keyListID uuid.UUID, EncSymKey []byte) (err error) {
	KeyListJSON, found := userlib.DatastoreGet(keyListID)
	if found == false {
		return fmt.Errorf("Cannot find the keyList with ID: %v", keyListID)
	}
	var keyList KeyList
	err = json.Unmarshal(KeyListJSON, &keyList)
	if err != nil {
		return fmt.Errorf("Error occurred when unmarshaling keylistJSON" + err.Error())
	}
	keyList.List = append(keyList.List, EncSymKey)
	keyListJSON, err := json.Marshal(keyList)
	if err != nil {
		return fmt.Errorf("Error occurred when unmarshaling keylistJSON" + err.Error())
	}
	userlib.DatastoreSet(keyListID, keyListJSON)

	return err
}
func (userdata *User) sendFileToStore(FileID uuid.UUID, Fileptr *File) (err error) {
	marshal, err := json.Marshal(*Fileptr)
	if err != nil {
		return fmt.Errorf("An error occurred while transforming File to JSON: " + err.Error())
	}
	SymKey := userlib.RandomBytes(16)
	pubSymKeyEnc, ok := userlib.KeystoreGet(userdata.UserID.String() + "SymKey")
	if ok == false {
		return fmt.Errorf("Cannot get %v from keystore", userdata.UserID.String()+"SymKey")
	}
	EncSymKey, err := userlib.PKEEnc(pubSymKeyEnc, SymKey)
	keyListID, err := uuid.FromBytes(userlib.Hash([]byte("Key" + FileID.String())))
	err = userdata.sendKeyToStore(keyListID, EncSymKey)
	IV := userlib.RandomBytes(16)
	cipher := userlib.SymEnc(SymKey, IV, marshal)
	var filePackage FilePackage
	filePackage.FileJSON = cipher
	filePackage.FileSign, err = userlib.DSSign(userdata.PrivKeyFileSign, cipher)
	marshal, err = json.Marshal(filePackage)
	var DecFilePackage FilePackage
	err = json.Unmarshal(marshal, &DecFilePackage)
	if err != nil {
		return fmt.Errorf("An error occurred while converting filePackage to JSON: " + err.Error())
	}
	userlib.DatastoreSet(FileID, marshal)
	return err
}

func (userdata *User) getFileFromStore(FileID uuid.UUID) (FilePtr *File, found bool, err error) {
	fileJSON, exist := userlib.DatastoreGet(FileID) //DOWNLOAD here
	if exist == false {
		return nil, false, nil
	}
	var filePackage FilePackage
	err = json.Unmarshal(fileJSON, &filePackage)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot deserialize the message for FilePackage: " + err.Error())
	}
	sign := filePackage.FileSign
	msg := filePackage.FileJSON
	pubKeyFileSign, exist := userlib.KeystoreGet(userdata.UserID.String() + "FileSign")
	if exist == false {
		return nil, false, fmt.Errorf("Cannot get the public key for signing File: ")
	}
	err = userlib.DSVerify(pubKeyFileSign, msg, sign)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot verify the signature for File: " + err.Error())
	}
	fileEncKey, err := userlib.HashKDF(userdata.RootKey, []byte("FileEnc"))
	if err != nil {
		return nil, false, fmt.Errorf("An error occurred during hashKDF: " + err.Error())
	}
	decMsg := userlib.SymDec(fileEncKey[:16], msg)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot decrypt the message for File: " + err.Error())
	}
	var File File
	err = json.Unmarshal(decMsg, &File)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot deserialize the message for File: " + err.Error())
	}
	return &File, true, err
}

func (userdata *User) sendFileAppendToStore(FAID uuid.UUID, FileAppendptr *FileAppend) (err error) {
	marshal, err := json.Marshal(*FileAppendptr)
	if err != nil {
		return fmt.Errorf("An error occurred while transforming FileAppend to JSON: " + err.Error())
	}
	var IV = userlib.RandomBytes(16)
	fileAppendEncKey, err := userlib.HashKDF(userdata.RootKey, []byte("FileAppendEnc"))
	if err != nil {
		return fmt.Errorf("An error occurred during hashKDF: " + err.Error())
	}
	cipher := userlib.SymEnc(fileAppendEncKey[:16], IV, marshal)
	var FileAppendPackage FileAppendPackage
	FileAppendPackage.FileAppendJSON = cipher
	FileAppendPackage.FileAppendSign, err = userlib.DSSign(userdata.PrivKeyFileAppendSign, cipher)
	if err != nil {
		return fmt.Errorf("An error occurred while decrypting FileAppend: " + err.Error())
	}
	marshal, err = json.Marshal(FileAppendPackage)
	if err != nil {
		return fmt.Errorf("An error occurred while transforming FileAppendPackage to JSON: " + err.Error())
	}

	userlib.DatastoreSet(FAID, marshal)
	return err
}

func (userdata *User) getFileAppendFromStore(FAID uuid.UUID) (FileAppendPtr *FileAppend, found bool, err error) {
	FileAppendJSON, found := userlib.DatastoreGet(FAID) //DOWNLOAD here
	if found == false {
		userlib.DebugMsg("Cannot find the fileAppend in ID: %v", FAID)
		return nil, false, nil
	}
	var FileAppendPackage FileAppendPackage
	err = json.Unmarshal(FileAppendJSON, &FileAppendPackage)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot deserialize the message for FileAppendPackage: " + err.Error())
	}
	sign := FileAppendPackage.FileAppendSign
	msg := FileAppendPackage.FileAppendJSON
	pubKeyFileAppendSign, exist := userlib.KeystoreGet(userdata.UserID.String() + "FileAppendSign")
	if exist == false {
		return nil, false, fmt.Errorf("Cannot get the public key for signing FileAppend: ")
	}
	pubKeyFileAppendSign, ok := userlib.KeystoreGet(userdata.UserID.String() + "FileAppendSign")
	if ok == false {
		return nil, false, fmt.Errorf("Error occurred when getting FileAppend key from KeyStore")
	}
	err = userlib.DSVerify(pubKeyFileAppendSign, msg, sign)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot verify the signature for FileAppend: " + err.Error())
	}
	fileAppendEncKey, err := userlib.HashKDF(userdata.RootKey, []byte("FileAppendEnc"))
	if err != nil {
		return nil, false, fmt.Errorf("An error occurred during hashKDF: " + err.Error())
	}
	decMsg := userlib.SymDec(fileAppendEncKey[:16], msg)
	var FileAppend FileAppend
	err = json.Unmarshal(decMsg, &FileAppend)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot deserialize the message for FileAppend: " + err.Error())
	}
	return &FileAppend, true, err
}

func (userdata *User) sendInvitationToStore(InvitationID uuid.UUID, Invitationptr *Invitation) (err error) {

	recipientKey, ok := userlib.KeystoreGet(Invitationptr.AcceptorID.String() + "InviteEnc")
	if ok == false {
		return fmt.Errorf("An error occurred while getting recipient Invite Key: ")
	}
	/*
		var IV = userlib.RandomBytes(16)
		invitationEncKey, err := userlib.HashKDF(userdata.RootKey, []byte("InviteEnc"))
		if err != nil {
			return fmt.Errorf("An error occurred during hashKDF: " + err.Error()))
		}
	*/
	//cipher := userlib.SymEnc(invitationEncKey[:16], IV, marshal)
	/*
		Invitationptr.CreatorID, err = userlib.PKEEnc(recipientKey, json.Marshal(Invitationptr.CreatorID))
		if err != nil {
			return fmt.Errorf("An error occurred while encrypting CreatorID: " + err.Error()))
		}
		Invitationptr.CreatorName, err = userlib.PKEEnc(recipientKey, json.Marshal(Invitationptr.CreatorName))
		if err != nil {
			return fmt.Errorf("An error occurred while encrypting CreatorName: " + err.Error()))
		}
		Invitationptr.AcceptorID, err = userlib.PKEEnc(recipientKey, json.Marshal(Invitationptr.AcceptorID))
		if err != nil {
			return fmt.Errorf("An error occurred while encrypting CreatorName: " + err.Error()))
		}
		Invitationptr.FileID, err = userlib.PKEEnc(recipientKey, json.Marshal(Invitationptr.FileID))
		if err != nil {
			return fmt.Errorf("An error occurred while encrypting CreatorName: " + err.Error()))
		}
		Invitationptr.InvitationID, err = userlib.PKEEnc(recipientKey, json.Marshal(Invitationptr.InvitationID))
		if err != nil {
			return fmt.Errorf("An error occurred while encrypting CreatorName: " + err.Error()))
		}
		Invitationptr.InvitationParentPtr, err = userlib.PKEEnc(recipientKey, json.Marshal(Invitationptr.InvitationParentPtr))
		if err != nil {
			return fmt.Errorf("An error occurred while encrypting CreatorName: " + err.Error()))
		}
	*/
	marshal, err := json.Marshal(*Invitationptr)
	if err != nil {
		return fmt.Errorf("An error occurred while transforming Invitation to JSON: " + err.Error())
	}
	//userlib.DebugMsg("before PKEEnc: %v", marshal)
	//cipher16, err := userlib.PKEEnc(recipientKey, marshal[:16])
	//var combined []byte
	//userlib.DebugMsg("encrypting the first 16: %v", cipher16)
	//combined = append(combined, cipher16...)
	//combined = append(combined, marshal[16:]...)
	//userlib.DebugMsg("combining: %v", combined)
	//if err != nil {
	//	return fmt.Errorf("An error occurred while encrypting marshal for invitation: " + err.Error()))
	//}
	var InvitationPackage InvitationPackage
	InvitationPackage.InvitationJSON = marshal
	userlib.DebugMsg("user who is encrypting invitation: %v", userdata.UserID)

	InvitationPackage.InvitationSign, err = userlib.DSSign(userdata.PrivKeyInviteSign, marshal)
	var creatorIDString string
	creatorIDString = Invitationptr.CreatorID.String()
	if err != nil {
		return fmt.Errorf("An error occurred while converting creatorID to string")
	}
	encryptedCreatorID, err := userlib.PKEEnc(recipientKey, []byte(creatorIDString))
	if err != nil {
		return fmt.Errorf("An error occurred while encrypting plainCreatorID for invitation: " + err.Error())
	}
	InvitationPackage.CreatorIDByte = encryptedCreatorID
	packageMarshal, err := json.Marshal(InvitationPackage)
	if err != nil {
		return fmt.Errorf("An error occurred while converting invitationPackage to JSON: " + err.Error())
	}
	userlib.DatastoreSet(InvitationID, packageMarshal)
	return err
}

func (userdata *User) getInvitationFromStore(InvitationID uuid.UUID) (InvitationPtr *Invitation, found bool, err error) {
	InvitationJSON, found := userlib.DatastoreGet(InvitationID) //DOWNLOAD here
	userlib.DebugMsg("invitationID: %v", InvitationID)
	userlib.DebugMsg("found invitation: %v", found)

	if found == false {
		return nil, false, nil
	}
	var InvitationPackage InvitationPackage
	err = json.Unmarshal(InvitationJSON, &InvitationPackage)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot deserialize the message for InvitationPackage: " + err.Error())
	}
	sign := InvitationPackage.InvitationSign
	msg := InvitationPackage.InvitationJSON

	creatorID := InvitationPackage.CreatorIDByte
	plainCreatorID, err := userlib.PKEDec(userdata.PrivKeyInviteEnc, creatorID)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot decrypt the CreatorID for InvitationPackage: " + err.Error())
	}
	pubKeyCreatorInviteSign, ok := userlib.KeystoreGet(string(plainCreatorID) + "InviteSign")
	if ok == false {
		return nil, false, fmt.Errorf("Error occurred when getting Creator's InviteSign key from KeyStore")

	}
	err = userlib.DSVerify(pubKeyCreatorInviteSign, msg, sign)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot verify the signature for InvitationPackage: " + err.Error())
	}
	/*
		recipientKey := userdata.PrivKeyInviteEnc

		plainMsg16, err := userlib.PKEDec(recipientKey, msg16)
		if err != nil {
			return fmt.Errorf("Cannot decrypt the first 16 byte for msg: " + err.Error()))
		}
		var combined []byte
		combined = append(combined, plainMsg16...)
		combined = append(combined, msg16plus...)
		if err != nil {
			return fmt.Errorf("Cannot decrypt the message for InvitationPackage: " + err.Error()))
		}
	*/
	var Invitationptr Invitation
	err = json.Unmarshal(msg, &Invitationptr)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot deserialize the message for Invitation: " + err.Error())
	}

	return &Invitationptr, true, err
}

func (userdata *User) getCreator(Username string, Filename string) (CreatorID uuid.UUID, CreatorName string, err error) {
	UserID, err := uuid.FromBytes(userlib.Hash([]byte(Username))[:16])
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("An error occurred while creating UserID: " + err.Error())
	}
	InvitationID, err := uuid.FromBytes(userlib.Hash([]byte("Invitation" + UserID.String() + Filename))[:16])
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("An error occurred while creating InvitationID: " + err.Error())
	}
	Invitation, found, err := userdata.getInvitationFromStore(InvitationID)
	if found == false {
		return UserID, Username, nil
	} else {
		var CreatorID uuid.UUID
		var CreatorName string
		var cont = true
		for cont == true {

			if Invitation.IsAccepted == false || Invitation.IsRevoked == true {
				CreatorID = uuid.Nil
				CreatorName = ""
				cont = false
			}
			if Invitation.InvitationParentPtr == uuid.Nil {
				CreatorID = Invitation.CreatorID
				CreatorName = Invitation.CreatorName
				cont = false
			} else {
				InvitationParent, foundParent, err := userdata.getInvitationFromStore(Invitation.InvitationParentPtr) //DOWNLOAD
				if err != nil {
					return uuid.Nil, "", fmt.Errorf("An error occurred while getting Invitation from store: " + err.Error())
				}
				if foundParent == true {
					Invitation = InvitationParent
				}
			}
		}
		return CreatorID, CreatorName, err
	}

}
func (userdata *User) authorize(UserID uuid.UUID, Filename string) (success bool, err error) {
	//1. from UserID + FileID -> Invitation Object
	//2. While loop to check the root of InvitationParentPtr, add another check for IsRevoked, IsAccepted
	//3. Compare root.CreatorID == File.CreatorID
	InvitationID, err := uuid.FromBytes(userlib.Hash([]byte("Invitation" + UserID.String() + Filename))[:16])
	if err != nil {
		return false, fmt.Errorf("cannot create Invitation ID")
	}
	Invitation, found, err := userdata.getInvitationFromStore(InvitationID)
	if found == false {
		return true, nil //the person is the Creator of the File
	} else {
		var cont = true
		var authorized = false
		for cont == true {

			if Invitation.IsAccepted == false || Invitation.IsRevoked == true {
				authorized = false
				cont = false
			}
			if Invitation.InvitationParentPtr == uuid.Nil {
				authorized = true
				cont = false
			} else {
				InvitationParent, foundParent, err := userdata.getInvitationFromStore(InvitationID)
				if err != nil {
					return false, fmt.Errorf("An error occurred when getting invitation from store")
				}
				if foundParent == true {
					Invitation = InvitationParent
				}
			}
		}
		return authorized, err
	}

}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(Username string, Password string) (userdataptr *User, err error) {

	if len(Username) == 0 {
		return nil, fmt.Errorf("Empty Username provided")
	}

	var userdata User
	var pubKeyFileEnc userlib.PKEEncKey
	var pubKeyFileAppendEnc userlib.PKEEncKey
	var pubKeyInviteEnc userlib.PKEEncKey
	var pubKeyUserSign userlib.DSVerifyKey
	var pubKeyFileSign userlib.DSVerifyKey
	var pubKeyFileAppendSign userlib.DSVerifyKey
	var pubKeyInviteSign userlib.DSVerifyKey
	var pubSymKeyEnc userlib.PKEEncKey
	//SymKey -> encrypt symmetric key
	//pubKeyXSign -> Alice sign X, and Bob uses pubKey to verify
	userdata.Username = Username
	userdata.Salt = userlib.RandomBytes(16)
	userdata.RootKey = userlib.Argon2Key([]byte(Password), userdata.Salt, 16)
	userdata.FilesCreated = make(map[string]uuid.UUID)
	userdata.FilesSharedToMe = make(map[string]uuid.UUID)
	userdata.UsersSharedToMe = make(map[string]uuid.UUID)
	userdata.PrivSymKeyEnc, pubSymKeyEnc, err = userlib.DSKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling DSKeyGen(): " + err.Error())
	}
	userdata.PrivKeyUserSign, pubKeyUserSign, err = userlib.DSKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling DSKeyGen(): " + err.Error())
	}
	userdata.PrivKeyFileSign, pubKeyFileSign, err = userlib.DSKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling DSKeyGen(): " + err.Error())
	}
	userdata.PrivKeyFileAppendSign, pubKeyFileAppendSign, err = userlib.DSKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling DSKeyGen(): " + err.Error())
	}
	userdata.PrivKeyInviteSign, pubKeyInviteSign, err = userlib.DSKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling DSKeyGen(): " + err.Error())
	}
	pubKeyFileEnc, userdata.PrivKeyFileEnc, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling PKEKeyGen(): " + err.Error())
	}
	pubKeyFileAppendEnc, userdata.PrivKeyFileAppendEnc, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling PKEKeyGen(): " + err.Error())
	}
	pubKeyInviteEnc, userdata.PrivKeyInviteEnc, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling PKEKeyGen(): " + err.Error())
	}
	userdata.UserID, err = uuid.FromBytes(userlib.Hash([]byte(Username))[:16])
	if err != nil {
		return nil, fmt.Errorf("An error occurred while creating UserID: " + err.Error())
	}
	userlib.DebugMsg("creating User: Name: %v, ID: %v", userdata.Username, userdata.UserID)

	_, exist, err := getUserFromStore(userdata.UserID, Password)
	if exist {
		return nil, fmt.Errorf("Error: Username [" + Username + "] is already created.")
	}
	err = userlib.KeystoreSet(userdata.UserID.String()+"SymKey", pubSymKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling KeystoreSet()")
	}
	err = userlib.KeystoreSet(userdata.UserID.String()+"FileEnc", pubKeyFileEnc)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling KeystoreSet()")
	}
	err = userlib.KeystoreSet(userdata.UserID.String()+"FileAppendEnc", pubKeyFileAppendEnc)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling KeystoreSet()")
	}
	err = userlib.KeystoreSet(userdata.UserID.String()+"InviteEnc", pubKeyInviteEnc)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling KeystoreSet()")
	}
	err = userlib.KeystoreSet(userdata.UserID.String()+"UserSign", pubKeyUserSign)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling KeystoreSet()")
	}
	err = userlib.KeystoreSet(userdata.UserID.String()+"FileSign", pubKeyFileSign)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling KeystoreSet()")
	}
	err = userlib.KeystoreSet(userdata.UserID.String()+"FileAppendSign", pubKeyFileAppendSign)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling KeystoreSet()")
	}
	err = userlib.KeystoreSet(userdata.UserID.String()+"InviteSign", pubKeyInviteSign)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling KeystoreSet()")
	}
	sendUserToStore(userdata.UserID, &userdata)

	return &userdata, err
}

func GetUser(Username string, Password string) (userdataptr *User, err error) {

	var userdata User
	userdataptr = &userdata

	UserID, err := uuid.FromBytes(userlib.Hash([]byte(Username))[:16])
	if err != nil {
		return nil, fmt.Errorf("Cannot create UserID")
	}
	user, exist, err := getUserFromStore(UserID, Password)
	if exist == false {
		return nil, fmt.Errorf("User not found")
	}
	// Wait approx 2 seconds to prevent dictionary attack
	// We cannot import time so, we use a while loop to simulate
	/*
	   var c = 0

	   for c < (1000000 * 10) {

	     // junk operations
	     b, err := strconv.ParseBool("false")
	     f, err := strconv.ParseFloat("100.1241232123", 64)
	     i, err := strconv.ParseInt("99", 10, 64)
	     u, err := strconv.ParseUint("-99", 10, 64)

	     c++

	   }
	*/ // omit this code first

	return user, err

}

func (userdata *User) StoreFile(Filename string, Content []byte) (err error) {
	userlib.DebugMsg(" ==== In storeFile ====")

	authorized, err := userdata.authorize(userdata.UserID, Filename)
	userdata, err = getUserFromStoreByRootKey(userdata.UserID, userdata.RootKey)
	if authorized == false {
		return fmt.Errorf("User is not authorized to store this File")
	}

	var File File
	File.Content = Content
	CreatorID, _, err := userdata.getCreator(userdata.Username, Filename)
	if CreatorID == uuid.Nil {
		return fmt.Errorf("Cannot find Creator for this File")
	}
	File.FileID, err = uuid.FromBytes(userlib.Hash([]byte(CreatorID.String() + Filename))[:16])
	userlib.DebugMsg("fileID calculated from: %v", CreatorID.String()+Filename)
	userlib.DebugMsg("FileID in storeFile: %v", File.FileID)
	if err != nil {
		return fmt.Errorf("An error occurred while creating FileID: " + err.Error())
	}
	File.CreatorID = CreatorID
	userlib.DebugMsg("current userID: %v, username: %v", userdata.UserID, userdata.Username)
	userlib.DebugMsg("File.CreatorID: %v", File.CreatorID)
	if userdata.UserID == File.CreatorID {
		userdata.FilesCreated[Filename] = File.FileID
		sendUserToStore(userdata.UserID, userdata)
		userlib.DebugMsg("After updating FilesCreated: %v", userdata.FilesCreated)

	}

	userdata.sendFileToStore(File.FileID, &File)

	var FileAppend FileAppend
	FileAppend.FAID, err = uuid.FromBytes(userlib.Hash([]byte("Append" + File.CreatorID.String() + Filename))[:16])
	userlib.DebugMsg("FAID calculated from: %v, value: %v", "Append"+File.CreatorID.String()+Filename, FileAppend.FAID)

	if err != nil {
		return fmt.Errorf("An error occurred while creating FAID: " + err.Error())
	}
	//FileAppend.CreatorID = File.CreatorID
	FileAppend.MFID = File.FileID
	var emptyContents = []uuid.UUID{}
	FileAppend.AP = emptyContents
	userdata.sendFileAppendToStore(FileAppend.FAID, &FileAppend)

	userlib.DebugMsg(" ==== End storeFile ====")

	return err

}

func (userdata *User) AppendToFile(Filename string, Content []byte) (err error) {
	userlib.DebugMsg(" ==== Start AppendToFile ===== ")
	userdata, err = getUserFromStoreByRootKey(userdata.UserID, userdata.RootKey)
	authorized, err := userdata.authorize(userdata.UserID, Filename)
	if authorized == false {
		return fmt.Errorf("User is not authorized to append to this File")
	}
	CreatorID, _, err := userdata.getCreator(userdata.Username, Filename)
	userlib.DebugMsg("Creator in AppendToFile: %v", CreatorID)
	if CreatorID == uuid.Nil {
		return fmt.Errorf("Cannot find the Creator for this File: ")
	}
	FAID, err := uuid.FromBytes(userlib.Hash([]byte("Append" + CreatorID.String() + Filename))[:16])
	userlib.DebugMsg("Calculating FAID: %v", "Append"+CreatorID.String()+Filename)
	userlib.DebugMsg("FAID in AppendToFile: %v", FAID)
	if err != nil {
		return fmt.Errorf("An error occurred while creating FAID: " + err.Error())
	}
	MFID, err := uuid.FromBytes(userlib.Hash([]byte(CreatorID.String() + Filename))[:16])
	FileAppend, found, err := userdata.getFileAppendFromStore(FAID)
	userlib.DebugMsg("FileAppend Downloaded from DB: %v", FileAppend)

	if found == false {
		return fmt.Errorf("The File doesn't exist!" + err.Error())
	}
	var FileToAppend File
	FileToAppend.Content = Content
	FileToAppend.FileID, err = uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return fmt.Errorf("An error occurred while creating FileID for FileToAppend: " + err.Error())
	}
	FileToAppend.CreatorID = CreatorID
	userdata.sendFileToStore(FileToAppend.FileID, &FileToAppend) //UPLOAD
	FileAppend.MFID = MFID
	FileAppend.AP = append(FileAppend.AP, FileToAppend.FileID)
	FileAppend.FAID = FAID
	userdata.sendFileAppendToStore(FileAppend.FAID, FileAppend) //UPLOAD
	userlib.DebugMsg("FileApend: %v", FileAppend)
	userlib.DebugMsg(" ==== End AppendToFile ===== ")
	return err
}

func (userdata *User) LoadFile(Filename string) (Content []byte, err error) {
	userlib.DebugMsg(" ==== Start LoadFile ===== ")
	userdata, err = getUserFromStoreByRootKey(userdata.UserID, userdata.RootKey)
	authorized, err := userdata.authorize(userdata.UserID, Filename)
	if authorized == false {
		return []byte{}, fmt.Errorf("User is not authorized to append to this File")
	}
	CreatorID, _, err := userdata.getCreator(userdata.Username, Filename)
	if CreatorID == uuid.Nil {
		return []byte{}, fmt.Errorf("Cannot find Creator for this File")
	}
	userlib.DebugMsg("creatorID: %v", CreatorID)
	FileID, err := uuid.FromBytes(userlib.Hash([]byte(CreatorID.String() + Filename))[:16])
	if err != nil {
		return []byte{}, fmt.Errorf("An error occurred while creating FileID: " + err.Error())
	}
	userlib.DebugMsg("FileID: %v", FileID)
	File, foundFile, err := userdata.getFileFromStore(FileID)
	if foundFile == false {
		return []byte{}, fmt.Errorf("Cannot find this File")
	}
	var mainContent []byte
	mainContent = File.Content

	FAID, err := uuid.FromBytes(userlib.Hash([]byte("Append" + CreatorID.String() + Filename))[:16])
	if err != nil {
		return []byte{}, fmt.Errorf("An error occurred while creating FAID: " + err.Error())
	}
	FileAppend, foundFileAppend, err := userdata.getFileAppendFromStore(FAID)
	if foundFileAppend == false {
		return []byte{}, fmt.Errorf("Cannot find the FileAppend struct for this File")
	}
	for _, FAID := range FileAppend.AP {
		FileToAppend, foundFileToAppend, err := userdata.getFileFromStore(FAID)
		if err != nil {
			return []byte{}, fmt.Errorf("Error occurred when getting file from store")
		}
		if foundFileToAppend == false {
			return []byte{}, fmt.Errorf("Cannot find this File to append")
		}
		mainContent = append(mainContent, FileToAppend.Content...)
	}
	userlib.DebugMsg(" ==== End LoadFile ===== ")
	return mainContent, err
	/*
	   === UNMARSHAL CODE ===
	   dataJSON, ok := userlib.DatastoreGet(storageKey)
	   if !ok {
	     return nil, errors.New(strings.ToTitle("File not found"))
	   }
	   err = json.Unmarshal(dataJSON, &Content)
	   return Content, err
	*/
}

func (userdata *User) CreateInvitation(Filename string, recipientUsername string) (InvitationPtr uuid.UUID, err error) {
	userlib.DebugMsg(" ==== Start CreateInvitation ==== ")
	userdata, err = getUserFromStoreByRootKey(userdata.UserID, userdata.RootKey)
	userlib.DebugMsg("userdata.FilesCraeted: %v", userdata.FilesCreated)
	//1. Check File name is valid & authorized
	createdFileKeys := make([]string, 0, len(userdata.FilesCreated))

	for k, v := range userdata.FilesCreated {
		userlib.DebugMsg("printing loop in FilesCreated, k: %v, v: %v", k, v)
		createdFileKeys = append(createdFileKeys, k)
	}
	sharedFileKeys := make([]string, 0, len(userdata.FilesSharedToMe))

	for k, v := range userdata.FilesSharedToMe {
		userlib.DebugMsg("printing loop in FilesSharedToMe, k: %v, v: %v", k, v)

		sharedFileKeys = append(sharedFileKeys, k)
	}
	var createdContains = false
	var shareContains = false
	userlib.DebugMsg("current user: %v", userdata.Username)
	userlib.DebugMsg("createdFileKeys in createInvitation: %v", createdFileKeys)
	userlib.DebugMsg("sharedFileKeys: %v", sharedFileKeys)
	for _, v := range createdFileKeys {
		if v == Filename {
			createdContains = true
		}
	}

	for _, v := range sharedFileKeys {
		if v == Filename {
			shareContains = true
		}
	}
	if shareContains == false && createdContains == false {
		return uuid.Nil, fmt.Errorf("This File is not created by nor shared to this user")
	}
	//check recipient Username
	recipientUserID, err := uuid.FromBytes(userlib.Hash([]byte(recipientUsername))[:16])
	if err != nil {
		return uuid.Nil, fmt.Errorf("Cannot create recipientUserID" + err.Error())
	}
	CreatorID, CreatorName, err := userdata.getCreator(userdata.Username, Filename)
	if CreatorID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("Cannot find Creator for this File")
	}
	FileID, err := uuid.FromBytes(userlib.Hash([]byte(CreatorID.String() + Filename))[:16])
	if err != nil {
		return uuid.Nil, fmt.Errorf("Cannot create FileID" + err.Error())
	}
	var Invitation Invitation
	Invitation.CreatorID = CreatorID
	Invitation.CreatorName = CreatorName
	Invitation.AcceptorID, err = uuid.FromBytes(userlib.Hash([]byte(recipientUsername))[:16])
	if err != nil {
		return uuid.Nil, fmt.Errorf("Cannot create AcceptorID" + err.Error())
	}
	Invitation.FileID = FileID
	Invitation.IsAccepted = false
	Invitation.IsRevoked = false
	Invitation.InvitationID, err = uuid.FromBytes(userlib.Hash([]byte("Invitation" + recipientUserID.String() + Filename))[:16])
	if err != nil {
		return uuid.Nil, fmt.Errorf("Cannot create InvitationID" + err.Error())
	}
	userdata.sendInvitationToStore(Invitation.InvitationID, &Invitation)
	userlib.DebugMsg(" ==== End CreateInvitation ==== ")
	return Invitation.InvitationID, err
}

func (userdata *User) AcceptInvitation(senderUsername string, InvitationPtr uuid.UUID, Filename string) (err error) {
	userlib.DebugMsg(" ==== Start AcceptInvitation ==== ")
	userdata, err = getUserFromStoreByRootKey(userdata.UserID, userdata.RootKey)
	Invitation, success, err := userdata.getInvitationFromStore(InvitationPtr)

	if !success {
		return fmt.Errorf("Cannot find this Invitation")
	}
	CreatorID, _, err := userdata.getCreator(userdata.Username, Filename)
	if CreatorID == uuid.Nil {
		return fmt.Errorf("Cannot find CreatorID for this File ")
	}
	computedFileID, err := uuid.FromBytes(userlib.Hash([]byte(CreatorID.String() + Filename))[:16])
	userlib.DebugMsg("computing fileID...: %v, result: %v", CreatorID.String()+Filename, computedFileID)
	userlib.DebugMsg("FileID in invitation: %v", Invitation.FileID)
	if err != nil {
		return fmt.Errorf("Cannot create File ID")
	}
	if Invitation.FileID != computedFileID {
		return fmt.Errorf("The passed File name does not match")
	}
	computedSenderID, err := uuid.FromBytes(userlib.Hash([]byte(senderUsername))[:16])
	if err != nil {
		return fmt.Errorf("Cannot create Invitation sender ID")
	}
	if Invitation.CreatorID != computedSenderID {
		return fmt.Errorf("The passed sender Username does not match")
	}
	Invitation.IsAccepted = true
	userdata.FilesSharedToMe[Filename] = Invitation.FileID
	userdata.UsersSharedToMe[Filename] = Invitation.CreatorID
	sendUserToStore(userdata.UserID, userdata)
	userdata.sendInvitationToStore(InvitationPtr, Invitation)

	// If success is true, then returns an error {Invitation is not found, or it is revoked)
	// Decrypt the Invitation using user.PrivKey2(recipient’s Private Key)
	// If the decryption fails, then returns an error {given InvitationPtr was created by senderUsername}
	// Verify the signature in InvitationPackage by DSVerify using the sender's public key , and throw an error if error occurs {RSA Signature failed, tampering detected.}
	// If the above statements are executed successfully, then change the IsAccepted variable in InvitationFile and then JSON serialize it, use DatastoreSet to send it to DB
	userlib.DebugMsg(" ==== End AcceptInvitation ==== ")
	return err
}

func (userdata *User) RevokeAccess(Filename string, recipientUsername string) (err error) {
	userlib.DebugMsg(" ==== Start RevokeAccess ==== ")
	userdata, err = getUserFromStoreByRootKey(userdata.UserID, userdata.RootKey)
	recipientUserID, err := uuid.FromBytes(userlib.Hash([]byte(recipientUsername))[:16])
	if err != nil {
		return fmt.Errorf("Cannot create recipientUser ID" + err.Error())
	}

	InvitationID, err := uuid.FromBytes(userlib.Hash([]byte("Invitation" + recipientUserID.String()))[:16])
	if err != nil {
		return fmt.Errorf("Cannot create Invitation ID" + err.Error())
	}
	Invitation, foundInvitation, err := userdata.getInvitationFromStore(InvitationID)
	if foundInvitation == false {
		return fmt.Errorf("Cannot find the Invitation object")
	}
	Invitation.IsRevoked = false

	var FilesSharedToMe map[string]uuid.UUID

	for k, v := range userdata.FilesSharedToMe {
		if v != Invitation.FileID {
			FilesSharedToMe[k] = v
		}
	}
	userdata.FilesSharedToMe = FilesSharedToMe
	var UsersSharedToMe map[string]uuid.UUID

	for k, v := range userdata.UsersSharedToMe {
		if v != Invitation.CreatorID {
			UsersSharedToMe[k] = v
		}
	}
	userdata.UsersSharedToMe = UsersSharedToMe

	sendUserToStore(userdata.UserID, userdata)
	userdata.sendInvitationToStore(InvitationID, Invitation)
	userlib.DebugMsg(" ==== End RevokeAccess ==== ")
	return err
}
