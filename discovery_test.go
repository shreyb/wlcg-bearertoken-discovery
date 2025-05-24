package tokendiscovery_test

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"testing"

	disc "github.com/shreyb/wlcg-bearertoken-discovery"
)

func TestFindTokenAndFile(t *testing.T) {
	tokenFileTempDir := t.TempDir()
	curUser, err := user.Current()
	if err != nil {
		t.Error("Could not get current user from OS")
	}
	bearerTokenFile := filepath.Join(tokenFileTempDir, "bt_test_file")
	xdgTokenFile := filepath.Join(tokenFileTempDir, fmt.Sprintf("bt_u%s", curUser.Uid))
	fallthroughTokenFile := filepath.Join("/tmp", fmt.Sprintf("bt_u%s", curUser.Uid))

	type testCase struct {
		description  string
		setupFunc    func(*testing.T)
		expectedTok  []byte
		expectedPath string
		expectedErr  error
	}

	testCases := []testCase{
		{
			"BEARER_TOKEN defined",
			func(t *testing.T) {
				t.Setenv("BEARER_TOKEN", "42")
			},
			[]byte("42"),
			"",
			nil,
		},
		{
			"BEARER_TOKEN defined with extra spaces",
			func(t *testing.T) {
				t.Setenv("BEARER_TOKEN", "4 2 ")
			},
			[]byte("4 2"),
			"",
			nil,
		},
		{
			"BEARER_TOKEN defined, but empty - should move eventually to fallback",
			func(t *testing.T) {
				t.Setenv("BEARER_TOKEN", "")
				os.WriteFile(fallthroughTokenFile, []byte("abcde"), 0600)
				t.Cleanup(func() { os.Remove(fallthroughTokenFile) })
			},
			[]byte("abcde"),
			fallthroughTokenFile,
			nil,
		},
		{
			"BEARER_TOKEN_FILE defined",
			func(t *testing.T) {
				os.WriteFile(bearerTokenFile, []byte("12345"), 0600)
				t.Setenv("BEARER_TOKEN_FILE", bearerTokenFile)
			},
			[]byte("12345"),
			bearerTokenFile,
			nil,
		},
		{
			"BEARER_TOKEN_FILE defined with extra spaces",
			func(t *testing.T) {
				os.WriteFile(bearerTokenFile, []byte("    12  345  "), 0600)
				t.Setenv("BEARER_TOKEN_FILE", bearerTokenFile)
			},
			[]byte("12  345"),
			bearerTokenFile,
			nil,
		},
		{
			"BEARER_TOKEN_FILE defined with file that doesn't exist",
			func(t *testing.T) {
				os.Remove(bearerTokenFile)
				t.Setenv("BEARER_TOKEN_FILE", bearerTokenFile)
			},
			nil,
			"",
			errors.New("value for BEARER_TOKEN_FILE is set but the file does not exist on the filesystem"),
		},
		{
			"BEARER_TOKEN_FILE defined, but empty - should fall through",
			func(t *testing.T) {
				os.WriteFile(bearerTokenFile, []byte(""), 0600)
				t.Setenv("BEARER_TOKEN_FILE", bearerTokenFile)
				os.WriteFile(fallthroughTokenFile, []byte("btf_fallthrough"), 0600)
				t.Cleanup(func() { os.Remove(fallthroughTokenFile) })
			},
			[]byte("btf_fallthrough"),
			fallthroughTokenFile,
			nil,
		},
		{
			"XDG_RUNTIME_DIR defined, token file exists",
			func(t *testing.T) {
				os.WriteFile(xdgTokenFile, []byte("54321"), 0600)
				t.Setenv("XDG_RUNTIME_DIR", tokenFileTempDir)
			},
			[]byte("54321"),
			xdgTokenFile,
			nil,
		},
		{
			"XDG_RUNTIME_DIR defined, extra spaces in token",
			func(t *testing.T) {
				os.WriteFile(xdgTokenFile, []byte(" 543 21   "), 0600)
				t.Setenv("XDG_RUNTIME_DIR", tokenFileTempDir)
			},
			[]byte("543 21"),
			xdgTokenFile,
			nil,
		},
		{
			"XDG_RUNTIME_DIR defined, token file does not exist",
			func(t *testing.T) {
				tempDir2 := t.TempDir()
				t.Setenv("XDG_RUNTIME_DIR", tempDir2)
			},
			nil,
			"",
			errors.New("XDG_RUNTIME_DIR is set but the token file does not exist on the filesystem"),
		},
		{
			"XDG_RUNTIME_DIR defined, token file is empty - should move to next case",
			func(t *testing.T) {
				tempDir3 := t.TempDir()
				fname := filepath.Join(tempDir3, fmt.Sprintf("bt_u%s", curUser.Uid))
				os.WriteFile(fname, []byte(""), 0600)
				os.WriteFile(fallthroughTokenFile, []byte("xdg_fallthrough"), 0600)
				t.Setenv("XDG_RUNTIME_DIR", tempDir3)
				t.Cleanup(func() { os.Remove(fallthroughTokenFile) })
			},
			[]byte("xdg_fallthrough"),
			fallthroughTokenFile,
			nil,
		},
		{
			"Fallback - token in /tmp/bt_u$(id -u)",
			func(t *testing.T) {
				os.WriteFile(fallthroughTokenFile, []byte("56789"), 0600)
				t.Cleanup(func() { os.Remove(fallthroughTokenFile) })
			},
			[]byte("56789"),
			fallthroughTokenFile,
			nil,
		},
		{
			"Fallback - token in /tmp/bt_u$(id -u), with space",
			func(t *testing.T) {
				os.WriteFile(fallthroughTokenFile, []byte(" 5678 9  "), 0600)
				t.Cleanup(func() { os.Remove(fallthroughTokenFile) })
			},
			[]byte("5678 9"),
			fallthroughTokenFile,
			nil,
		},
		{
			"fallback case, but token is empty",
			func(t *testing.T) {
				os.WriteFile(fallthroughTokenFile, []byte(""), 0600)
				t.Cleanup(func() { os.Remove(fallthroughTokenFile) })
			},
			nil,
			"",
			disc.ErrNoTokenFound,
		},
		{
			"Fallback case, but token isn't there",
			func(*testing.T) {
				os.Remove(fallthroughTokenFile)
			},
			nil,
			"",
			disc.ErrNoTokenFound,
		},
	}
	for _, tc := range testCases {
		t.Run(
			tc.description,
			func(t *testing.T) {
				tc.setupFunc(t)
				tok, err := disc.FindToken()
				if !reflect.DeepEqual(tok, tc.expectedTok) {
					t.Errorf("Token strings do not match.  Expected %v, got %v", tc.expectedTok, tok)
				}
				if tc.expectedErr != nil && err == nil {
					t.Error("Expected non-nil error, but got nil")
					if !errors.Is(tc.expectedErr, err) {
						t.Errorf("Got different errors: expected %s, got %s", tc.expectedErr, err)
					}
				}
			},
		)
	}
}
