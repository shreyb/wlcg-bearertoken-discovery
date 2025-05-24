package tokendiscovery

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// ErrNoTokenFound indicates that the WLCG Bearer Token Discovery procedure failed to find a suitable bearer token
var ErrNoTokenFound = errors.New("no token found using WLCG Bearer Token Discovery procedure")

// FindToken follows the WLCG Bearer Token Discovery procedure to locate a bearer token on the user's machine
func FindToken() ([]byte, error) {
	tok, _, err := FindTokenAndFile()
	return tok, err
}

// FindTokenAndFile follows the WLCG Bearer Token Discovery procedure to locate a bearer token on the user's machine. It returns a byte slice of the token contents, a string indicating the path to the file containing the token, if applicable, and an error value indicating success or failure.
func FindTokenAndFile() ([]byte, string, error) {
	// 1. If the BEARER_TOKEN environment variable is set, then the value is taken to be the token contents.
	if retVal := strings.TrimSpace(os.Getenv("BEARER_TOKEN")); retVal != "" {
		return []byte(retVal), "", nil
	}

	// 2. If the BEARER_TOKEN_FILE environment variable is set, then its value is interpreted as a filename. The contents of the specified file are taken to be the token contents.
	if fname := os.Getenv("BEARER_TOKEN_FILE"); fname != "" {
		tok, err := readTokenFile(fname)
		switch {
		case os.IsNotExist(err):
			return nil, "", ErrNoTokenFound
		case errors.Is(err, errEmptyToken):
			// Do nothing - pass
		case err != nil:
			return nil, "", fmt.Errorf("cannot read token file located at %s: %w", fname, err)
		default:
			return tok, fname, nil
		}
	}

	// 3. If the XDG_RUNTIME_DIR environment variable is set, then take the token from the contents of $XDG_RUNTIME_DIR/bt_u$ID.
	curUser, err := user.Current()
	if err != nil {
		return nil, "", errors.New("could not get current user from OS")
	}

	if xdgDir := os.Getenv("XDG_RUNTIME_DIR"); xdgDir != "" {
		fname := filepath.Join(xdgDir, fmt.Sprintf("bt_u%s", curUser.Uid))
		tok, err := readTokenFile(fname)
		switch {
		case os.IsNotExist(err):
			return nil, "", ErrNoTokenFound
		case errors.Is(err, errEmptyToken):
			// Do nothing - pass
		case err != nil:
			return nil, "", fmt.Errorf("cannot read token file located at %s: %w", fname, err)
		default:
			return tok, fname, nil
		}
	}

	// 4. Otherwise, take the token from /tmp/bt_u$ID
	fname := filepath.Join("/tmp", fmt.Sprintf("bt_u%s", curUser.Uid))
	tok, err := readTokenFile(fname)
	switch {
	case (os.IsNotExist(err) || errors.Is(err, errEmptyToken)):
		return nil, "", ErrNoTokenFound
	case err != nil:
		return nil, "", fmt.Errorf("cannot read token file located at %s: %w", fname, err)
	}

	return tok, fname, nil
}

func readTokenFile(path string) ([]byte, error) {
	tok, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Handle empty token case
	retTok := bytes.TrimSpace(tok)
	if len(retTok) == 0 {
		return nil, errEmptyToken
	}

	return retTok, nil
}

var (
	errEmptyToken = errors.New("token file has no data")
	errReadToken  = errors.New("cannot read token file")
)
