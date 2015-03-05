// Package httpauth implements cookie/session based authentication and
// authorization. Intended for use with the net/http or github.com/gorilla/mux
// packages, but may work with github.com/codegangsta/martini as well.
// Credentials are stored as a username + password hash, computed with bcrypt.
//
// Three user storage systems are currently implemented: file based
// (encoding/gob), sql databases (database/sql), and MongoDB databases.
//
// Access can be restricted by a users' role. A higher role will give more
// access.
//
// Users can be redirected to the page that triggered an authentication error.
//
// Messages describing the reason a user could not authenticate are saved in a
// cookie, and can be accessed with the Messages function.
//
// Example source can be found at
// https://github.com/apexskier/httpauth/blob/master/examples/server.go
package httpauth

import (
	"errors"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// ErrDeleteNull is returned by DeleteUser when that user didn't exist at the
// time of call.
// ErrMissingUser is returned by Users when a user is not found.
var (
	ErrDeleteNull  = mkerror("deleting non-existant user")
	ErrMissingUser = mkerror("can't find user")
)

// Role represents an interal role. Roles are essentially a string mapped to an
// integer. Roles must be greater than zero.
type Role int

// UserData represents a single user. It contains the users username, email,
// and role as well as a hash of their username and password. When creating
// users, you should not specify a hash; it will be generated in the Register
// and Update functions.
type UserData struct {
	Name  string `bson:"Name"`
	Email string `bson:"Email"`
	Hash  []byte `bson:"Hash"`
	Role  string `bson:"Role"`
}

// Authorizer structures contain the store of user session cookies a reference
// to a backend storage system.
type Authorizer struct {
	cookiejar   *sessions.CookieStore
	backend     AuthBackend
	defaultRole string
	roles       map[string]Role
}

// The AuthBackend interface defines a set of methods an AuthBackend must
// implement.
type AuthBackend interface {
	SaveUser(u UserData) error
	User(username string) (user UserData, e error)
	Users() (users []UserData, e error)
	DeleteUser(username string) error
	Close()
}

// Helper function to add a user directed message to a message queue.
func (a Authorizer) addMessage(rw http.ResponseWriter, req *http.Request, message string) {
	messageSession, _ := a.cookiejar.Get(req, "messages")
	defer messageSession.Save(req, rw)
	messageSession.AddFlash(message)
}

func mkerror(msg string) error {
	return errors.New("httpauth: " + msg)
}

// NewAuthorizer returns a new Authorizer given an AuthBackend, a cookie store
// key, a default user role, and a map of roles. If the key changes, logged in
// users will need to reauthenticate.
//
// Roles are a map of string to httpauth.Role values (integers). Higher Role values
// have more access.
//
// Example roles:
//
//     var roles map[string]httpauth.Role
//     roles["user"] = 2
//     roles["admin"] = 4
//     roles["moderator"] = 3
func NewAuthorizer(backend AuthBackend, key []byte, defaultRole string, roles map[string]Role) (Authorizer, error) {
	var a Authorizer
	a.cookiejar = sessions.NewCookieStore([]byte(key))
	a.backend = backend
	a.roles = roles
	a.defaultRole = defaultRole
	if _, ok := roles[defaultRole]; !ok {
		return a, mkerror("httpauth: defaultRole missing")
	}
	return a, nil
}

// Login logs a user in. They will be redirected to dest or to the last
// location an authorization redirect was triggered (if found) on success. A
// message will be added to the session on failure with the reason.
func (a Authorizer) Login(rw http.ResponseWriter, req *http.Request, u string, p string, dest string) error {
	session, _ := a.cookiejar.Get(req, "auth")
	if session.Values["username"] != nil {
		return mkerror("already authenticated")
	}
	if user, err := a.backend.User(u); err == nil {
		verify := bcrypt.CompareHashAndPassword(user.Hash, []byte(u+p))
		if verify != nil {
			a.addMessage(rw, req, "Invalid username or password.")
			return mkerror("password doesn't match")
		}
	} else {
		a.addMessage(rw, req, "Invalid username or password.")
		return mkerror("user not found")
	}
	session.Values["username"] = u
	session.Save(req, rw)

	redirectSession, _ := a.cookiejar.Get(req, "redirects")
	if flashes := redirectSession.Flashes(); len(flashes) > 0 {
		dest = flashes[0].(string)
	}
	http.Redirect(rw, req, dest, http.StatusSeeOther)
	return nil
}

// Register and save a new user. Returns an error and adds a message if the
// username is in use.
//
// Pass in a instance of UserData with at least a username and email specified. If no role
// is given, the default one is used.
func (a Authorizer) Register(rw http.ResponseWriter, req *http.Request, user UserData, password string) error {
	if user.Name == "" {
		return mkerror("no username given")
	}
	if user.Hash != nil {
		return mkerror("hash will be overwritten")
	}
	if password == "" {
		return mkerror("no password given")
	}

	// Validate username
	_, err := a.backend.User(user.Name)
	if err == nil {
		a.addMessage(rw, req, "Name has been taken.")
		return mkerror("user already exists")
	} else if err != ErrMissingUser {
		if err != nil {
			return mkerror(err.Error())
		}
		return nil
	}

	// Generate and save hash
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Name+password), 8)
	if err != nil {
		return mkerror("couldn't save password: " + err.Error())
	}
	user.Hash = hash

	// Validate role
	if user.Role == "" {
		user.Role = a.defaultRole
	} else {
		if _, ok := a.roles[user.Role]; !ok {
			return mkerror("non-existant role")
		}
	}

	err = a.backend.SaveUser(user)
	if err != nil {
		a.addMessage(rw, req, err.Error())
		return mkerror(err.Error())
	}
	return nil
}

// Update changes data for an existing user. Needs thought...
func (a Authorizer) Update(rw http.ResponseWriter, req *http.Request, p string, e string) error {
	var (
		hash  []byte
		email string
	)
	session, err := a.cookiejar.Get(req, "auth")
	username, ok := session.Values["username"].(string)
	if !ok {
		return mkerror("not logged in")
	}
	user, err := a.backend.User(username)
	if err == ErrMissingUser {
		a.addMessage(rw, req, "User doesn't exist.")
		return mkerror("user doesn't exists")
	} else if err != nil {
		return mkerror(err.Error())
	}
	if p != "" {
		hash, err = bcrypt.GenerateFromPassword([]byte(username+p), 8)
		if err != nil {
			return mkerror("couldn't save password: " + err.Error())
		}
	} else {
		hash = user.Hash
	}
	if e != "" {
		email = e
	} else {
		email = user.Email
	}

	newuser := UserData{username, email, hash, user.Role}

	err = a.backend.SaveUser(newuser)
	if err != nil {
		a.addMessage(rw, req, err.Error())
	}
	return nil
}

// ChangeRole changes the role for an existing user.
func (a Authorizer) ChangeRole(user *UserData, role string) error {
	var u UserData = *user
	u.Role = role
	return a.backend.SaveUser(u)
}

// Authorize checks if a user is logged in and returns an error on failed
// authentication. If redirectWithMessage is set, the page being authorized
// will be saved and a "Login to do that." message will be saved to the
// messages list. The next time the user logs in, they will be redirected back
// to the saved page.
func (a Authorizer) Authorize(rw http.ResponseWriter, req *http.Request) (*UserData, error) {
	session, err := a.cookiejar.Get(req, "auth")
	if err != nil {
		return nil, mkerror("new authorization session")
	}
	username := session.Values["username"]
	if username == nil {
		return nil, mkerror("user not logged in")
	}
	if name, ok := username.(string); ok {
		user, err := a.backend.User(name)
		if err == ErrMissingUser {
			session.Options.MaxAge = -1 // kill the cookie
			if rw != nil {
				session.Save(req, rw)
			}
			return nil, mkerror("user not found")
		} else if err != nil {
			return nil, mkerror(err.Error())
		}
		return &user, nil
	}
	return nil, mkerror("user not found")
}

// AuthorizeRole runs Authorize on a user, then makes sure their role is at
// least as high as the specified one, failing if not.
func (a Authorizer) Satisfy(user *UserData, role string) bool {
	r, ok := a.roles[role]
	if !ok {
		return false
	}
	return a.roles[user.Role] >= r
}

// Logout clears an authentication session and add a logged out message.
func (a Authorizer) Logout(rw http.ResponseWriter, req *http.Request) error {
	session, _ := a.cookiejar.Get(req, "auth")
	defer session.Save(req, rw)

	session.Options.MaxAge = -1 // kill the cookie
	a.addMessage(rw, req, "Logged out.")
	return nil
}

// DeleteUser removes a user from the Authorize. ErrMissingUser is returned if
// the user to be deleted isn't found.
func (a Authorizer) DeleteUser(username string) error {
	err := a.backend.DeleteUser(username)
	if err != nil && err != ErrDeleteNull {
		return mkerror(err.Error())
	}
	return err
}

// Messages fetches a list of saved messages. Use this to get a nice message to print to
// the user on a login page or registration page in case something happened
// (username taken, invalid credentials, successful logout, etc).
func (a Authorizer) Messages(rw http.ResponseWriter, req *http.Request) []string {
	session, _ := a.cookiejar.Get(req, "messages")
	flashes := session.Flashes()
	session.Save(req, rw)
	var messages []string
	for _, val := range flashes {
		messages = append(messages, val.(string))
	}
	return messages
}
