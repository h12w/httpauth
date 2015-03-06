package httpauth

import "fmt"

// MemAuthBackend stores user data and the location of the gob file.
type MemAuthBackend struct {
	users map[string]*UserData
}

// NewMemAuthBackend initializes a new backend by loading a map of users
// from a file.
// If the file doesn't exist, returns an error.
func NewMemAuthBackend() (b MemAuthBackend, e error) {
	b.users = make(map[string]*UserData)
	return b, nil
}

// User returns the user with the given username. Error is set to
// ErrMissingUser if user is not found.
func (b MemAuthBackend) User(username string) (user UserData, e error) {
	if user, ok := b.users[username]; ok {
		return *user, nil
	}
	return user, ErrMissingUser
}

// Users returns a slice of all users.
func (b MemAuthBackend) Users() (us []UserData, e error) {
	for _, user := range b.users {
		us = append(us, *user)
	}
	return
}

// SaveUser adds a new user, replacing one with the same username, and saves a
// gob file.
func (b MemAuthBackend) SaveUser(user UserData) error {
	b.users[user.Name] = &user
	return nil
}

// DeleteUser removes a user, raising ErrDeleteNull if that user was missing.
func (b MemAuthBackend) DeleteUser(username string) error {
	_, err := b.User(username)
	if err == ErrMissingUser {
		return ErrDeleteNull
	} else if err != nil {
		return fmt.Errorf("gobfilebackend: %v", err)
	}
	delete(b.users, username)
	return nil
}

// Close cleans up the backend. Currently a no-op for gobfiles.
func (b MemAuthBackend) Close() {

}
