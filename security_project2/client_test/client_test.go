package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Basic Test: Testing InitUser/GetUser on a single user.")
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("End Basic Test: Testing InitUser/GetUser on a single user.")
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("End Basic Test: Testing InitUser/GetUser on a single user.")
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
			userlib.DebugMsg("End Basic Test: Testing InitUser/GetUser on a single user.")
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.")
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", aliceFile)
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", aliceFile, contentTwo)
			err = bob.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
			userlib.DebugMsg("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.")
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Basic Test: Testing Revoke Functionality")
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("End Basic Test: Testing Revoke Functionality")
		})

	})

	Describe("Coverage Tests", func() {

		Specify("InitUser sanity check", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

		})

		Specify("GetUser sanity check", func() {

			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

		})

		Specify("StoreFile sanity check", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("filename", userlib.RandomBytes(10))
			Expect(err).To(BeNil())
		})

		Specify("LoadFile sanity check", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err := alice.LoadFile("filename")
			Expect(err).ToNot(BeNil())
		})

		Specify("AppendFile sanity check", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err := alice.AppendToFile("filename", userlib.RandomBytes(10))
			Expect(err).ToNot(BeNil())

		})

		Specify("CreateInvitation sanity check", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err := alice.CreateInvitation("filename", "bob")
			Expect(err).ToNot(BeNil())

		})

		Specify("AcceptInvitation sanity check", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			id, err := uuid.FromBytes(userlib.RandomBytes(10))
			err = alice.AcceptInvitation("filename", id, "bob")
			Expect(err).ToNot(BeNil())

		})

		Specify("RevokeAccess sanity check", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess("filename", "bob")
			Expect(err).ToNot(BeNil())

		})

		Specify("InitUser with empty username", func() {

			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())

		})

		Specify("GetUser only returns this newly created user with the correct password", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.GetUser("alice", "wrongPassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests whether unauthorized users have access to a file", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("filename", userlib.RandomBytes(10))
			Expect(err).To(BeNil())

			_, err = bob.LoadFile("filename")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests whether users can be authorized and deauthorized to access a file ", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("filename", userlib.RandomBytes(10))
			Expect(err).To(BeNil())

			invitationPtr, err := alice.CreateInvitation("filename", "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitationPtr, "filename")
			Expect(err).To(BeNil())

			_, err = bob.LoadFile("filename")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess("filename", "bob")
			Expect(err).To(BeNil())

			_, err = bob.LoadFile("filename")
			Expect(err).ToNot(BeNil())

		})

		Specify("Tests that a file content is the same across multiple sessions by having the original file creator modify a file", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("filename", userlib.RandomBytes(10))
			Expect(err).To(BeNil())

			invitationPtr, err := alice.CreateInvitation("filename", "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitationPtr, "filename")
			Expect(err).To(BeNil())

			content1, err := bob.LoadFile("filename")
			Expect(err).To(BeNil())

			err = alice.AppendToFile("filename", userlib.RandomBytes(10))
			Expect(err).To(BeNil())

			content2, err := bob.LoadFile("filename")
			Expect(err).To(BeNil())
			Expect(content1).ToNot(Equal(content2))

		})

		Specify("Tests whether an invitee can modify a file and its contents be reflected across all sessions", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("filename", userlib.RandomBytes(10))
			Expect(err).To(BeNil())

			invitationPtr, err := alice.CreateInvitation("filename", "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitationPtr, "filename")
			Expect(err).To(BeNil())

			err = bob.AppendToFile("filename", userlib.RandomBytes(10))
			Expect(err).To(BeNil())

			content1, err := bob.LoadFile("filename")
			Expect(err).To(BeNil())

			content2, err := alice.LoadFile("filename")
			Expect(err).To(BeNil())
			Expect(content1).To(Equal(content2))

		})

	})

})
