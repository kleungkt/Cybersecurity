package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
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

type User struct {
	Username              string
	Salt                  []byte
	UserID                uuid.UUID
	RootKey               []byte //TODO: still can't figure out the usage of RootKey
	privKeyEncMap						map[string]userlib.PKEDecKey
	PrivKeyUserSign       userlib.DSSignKey
	PrivKeyFileSign       userlib.DSSignKey
	PrivKeyFileAppendSign userlib.DSSignKey
	PrivKeyInvitationSign     userlib.DSSignKey
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
	Msg []byte
	Sign []byte
}

type FileAppend struct {
	MFID uuid.UUID //MainFileID
	AP   []uuid.UUID
	FAID uuid.UUID //FileAppendID
	//CreatorID    uuid.UUID
}
type FileAppendPackage struct {
	Msg []byte
	Sign []byte
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
	Msg []byte
	Sign [][]byte
	CreatorIDByte  []byte
}
type KeyList struct {
	List      [][]byte
	KeyListID uuid.UUID
}

/*Datastore:
| userID = hash(username) 			| UserPackage struct |
| fileID = hash(username + filename)| FilePackage struct |
| invitationID = hash("Invite" + recipientUsername + fileID ) | InvitationPackage Struct
| keyListID = hash("Key" + fileID) | KeyList struct |
| FileAppendID = hash("Append" + creatorID + fileID ) | FileAppendPackage Struct|
*/
/*Keystore:
|UserID + "UserSign" | pubKeyUserSign |
|UserID + "FileSign" | pubKeyFileSign |
|UserID + "FileAppendSign" | pubKeyFileAppendSign |
|UserID + "InvitationSign" | pubKeyInvitationSign |
|UserID + "SymKey" | pubSymKeyEnc |

*/

//Helper function
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

func (userdata * User) setStructToStore(ID uuid.UUID, CreatorID uuid.UUID, object * any, structType string) (err error) {
	marshal, err := json.Marshal(*object)
	if err != nil {
		return fmt.Errorf("An error occurred while transforming %v to JSON: " + err.Error(), structType)
	}
	var SymKey = userlib.RandomBytes(16)
	
} 
func (userdata * User) getStructFromStore(ID uuid.UUID, CreatorID uuid.UUID, structType string) (ret * any, found bool,  err error) {
	JSON, found := userlib.DatastoreGet(ID)
	if found == false {
		return nil, false, fmt.Errorf("Cannot find %v with ID: %v",  structType, ID)
	}
	var package any
	if structType == "File" {
		var empty FilePackage
		package = empty
	} else if structType == "FileAppend" {
		var empty FileAppendPackage
		package = empty
	} else if structType == "Invitation" {
		var empty InvitationPackage
		package = empty
	} else {
		return nil, false, fmt.Errorf("Not supported data type")
	}
	err = json.Unmarshal(JSON, &package)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot deserialize the message for %v: " + err.Error(), structType)
	}
	Sign := package.Sign
	Msg := package.Msg
	pubKeySign, exist := userlib.KeystoreGet(CreatorID.String() + structType + "Sign")
	if exist == false {
		return nil, false, fmt.Errorf("Cannot get the public key for signing %v: ", structType)
	}
	err = userlib.DSVerify(pubKeySign, Msg, Sign)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot verify the signature for %v: " + err.Error(), structType)
	}
	EncSymKey, err := userdata.getKeyFromStore()
	if err != nil {
		return nil, false, fmt.Errorf("Cannot get the public key for symmetric keys")
	}
	privKeyEnc := userdata.privKeyEncMap[structType]
	if privKeyEnc == nil {
		return nil, false, fmt.Errorf("Cannot get the private key for encryption")
	}
	plainSymKey, err := userlib.PKEDec(privKeyEnc, EncSymKey)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot decrypt the symmetric key")
	}
	DecMsg := userlib.SymDec(plainSymKey, Msg)
	var object any
	if structType == "File" {
		var empty File
		object = empty
	} else if structType == "FileAppend" {
		var empty FileAppend
		object = empty
	} else if structType == "Invitation" {
		var empty Invitation
		object = empty
	}
	err = json.Unmarshal(DecMsg, &object)
	if err != nil {
		return nil, false, fmt.Errorf("Cannot decrypt the %v", structType)
	}
	return &object, true, err
}
func InitUser(Username string, Password string) (userdataptr *User, err error) {

	if len(Username) == 0 {
		return nil, fmt.Errorf("Empty Username provided")
	}

	var userdata User
	var pubKeyFileEnc userlib.PKEEncKey
	var pubKeyFileAppendEnc userlib.PKEEncKey
	var pubKeyInvitationEnc userlib.PKEEncKey
	var pubKeyUserSign userlib.DSVerifyKey
	var pubKeyFileSign userlib.DSVerifyKey
	var pubKeyFileAppendSign userlib.DSVerifyKey
	var pubKeyInvitationSign userlib.DSVerifyKey
	var pubSymKeyEnc userlib.PKEEncKey

	//SymKey -> encrypt symmetric key
	//pubKeyXSign -> Alice sign X, and Bob uses pubKey to verify
	userdata.Username = Username
	userdata.Salt = userlib.RandomBytes(16)
	userdata.RootKey = userlib.Argon2Key([]byte(Password), userdata.Salt, 16)
	userdata.FilesCreated = make(map[string]uuid.UUID)
	userdata.FilesSharedToMe = make(map[string]uuid.UUID)
	userdata.UsersSharedToMe = make(map[string]uuid.UUID)
	userdata.privKeyEncMap = make(map[string]userlib.PKEDecKey)
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
	userdata.PrivKeyInvitationSign, pubKeyInvitationSign, err = userlib.DSKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling DSKeyGen(): " + err.Error())
	}
	var PrivKeyFileEnc userlib.PKEDecKey
	pubKeyFileEnc, PrivKeyFileEnc, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling PKEKeyGen(): " + err.Error())
	}
	userdata.privKeyEncMap["File"] = PrivKeyFileEnc
	var PrivKeyFileEnc userlib.PKEDecKey
	pubKeyFileAppendEnc, PrivKeyFileEnc, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling PKEKeyGen(): " + err.Error())
	}
	userdata.privKeyEncMap["FileAppend"] = PrivKeyFileEnc
	var PrivKeyInvitationEnc userlib.PKEDecKey
	pubKeyInvitationEnc, PrivKeyInvitationEnc, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling PKEKeyGen(): " + err.Error())
	}
	userdata.privKeyEncMap["Invitation"] = PrivKeyInvitationEnc
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
	err = userlib.KeystoreSet(userdata.UserID.String()+"InvitationEnc", pubKeyInvitationEnc)
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
	err = userlib.KeystoreSet(userdata.UserID.String()+"InvitationSign", pubKeyInvitationSign)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while calling KeystoreSet()")
	}
	sendUserToStore(userdata.UserID, &userdata)

	return &userdata, err
}
