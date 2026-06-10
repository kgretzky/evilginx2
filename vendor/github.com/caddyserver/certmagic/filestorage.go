// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"
)

// FileStorage facilitates forming file paths derived from a root
// directory. It is used to get file paths in a consistent,
// cross-platform way or persisting ACME assets on the file system.
// The presence of a lock file for a given key indicates a lock
// is held and is thus unavailable.
//
// Locks are created atomically by relying on the file system to
// enforce the O_EXCL flag. Acquirers that are forcefully terminated
// will not have a chance to clean up their locks before they exit,
// so locks may become stale. That is why, while a lock is actively
// held, the contents of the lockfile are updated with the current
// timestamp periodically. If another instance tries to acquire the
// lock but fails, it can see if the timestamp within is still fresh.
// If so, it patiently waits by polling occasionally. Otherwise,
// the stale lockfile is deleted, essentially forcing an unlock.
//
// While locking is atomic, unlocking is not perfectly atomic. File
// systems offer native atomic operations when creating files, but
// not necessarily when deleting them. It is theoretically possible
// for two instances to discover the same stale lock and both proceed
// to delete it, but if one instance is able to delete the lockfile
// and create a new one before the other one calls delete, then the
// new lock file created by the first instance will get deleted by
// mistake. This does mean that mutual exclusion is not guaranteed
// to be perfectly enforced in the presence of stale locks. One
// alternative is to lock the unlock operation by using ".unlock"
// files; and we did this for some time, but those files themselves
// may become stale, leading applications into infinite loops if
// they always expect the unlock file to be deleted by the instance
// that created it. We instead prefer the simpler solution that
// implies imperfect mutual exclusion if locks become stale, but
// that is probably less severe a consequence than infinite loops.
//
// See https://github.com/caddyserver/caddy/issues/4448 for discussion.
// See commit 468bfd25e452196b140148928cdd1f1a2285ae4b for where we
// switched away from using .unlock files.
type FileStorage struct {
	Path string
}

// Exists returns true if key exists in s.
func (s *FileStorage) Exists(_ context.Context, key string) bool {
	_, err := os.Stat(s.Filename(key))
	return !errors.Is(err, fs.ErrNotExist)
}

// Store saves value at key.
func (s *FileStorage) Store(_ context.Context, key string, value []byte) error {
	filename := s.Filename(key)
	err := os.MkdirAll(filepath.Dir(filename), 0700)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, value, 0600)
}

// Load retrieves the value at key.
func (s *FileStorage) Load(_ context.Context, key string) ([]byte, error) {
	return os.ReadFile(s.Filename(key))
}

// Delete deletes the value at key.
func (s *FileStorage) Delete(_ context.Context, key string) error {
	return os.Remove(s.Filename(key))
}

// List returns all keys that match prefix.
func (s *FileStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	var keys []string
	walkPrefix := s.Filename(prefix)

	err := filepath.Walk(walkPrefix, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info == nil {
			return fmt.Errorf("%s: file info is nil", fpath)
		}
		if fpath == walkPrefix {
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		suffix, err := filepath.Rel(walkPrefix, fpath)
		if err != nil {
			return fmt.Errorf("%s: could not make path relative: %v", fpath, err)
		}
		keys = append(keys, path.Join(prefix, suffix))

		if !recursive && info.IsDir() {
			return filepath.SkipDir
		}
		return nil
	})

	return keys, err
}

// Stat returns information about key.
func (s *FileStorage) Stat(_ context.Context, key string) (KeyInfo, error) {
	fi, err := os.Stat(s.Filename(key))
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{
		Key:        key,
		Modified:   fi.ModTime(),
		Size:       fi.Size(),
		IsTerminal: !fi.IsDir(),
	}, nil
}

// Filename returns the key as a path on the file
// system prefixed by s.Path.
func (s *FileStorage) Filename(key string) string {
	return filepath.Join(s.Path, filepath.FromSlash(key))
}

// Lock obtains a lock named by the given name. It blocks
// until the lock can be obtained or an error is returned.
func (s *FileStorage) Lock(ctx context.Context, name string) error {
	filename := s.lockFilename(name)

	// sometimes the lockfiles read as empty (size 0) - this is either a stale lock or it
	// is currently being written; we can retry a few times in this case, as it has been
	// shown to help (issue #232)
	var emptyCount int

	for {
		err := createLockfile(filename)
		if err == nil {
			// got the lock, yay
			return nil
		}
		if !os.IsExist(err) {
			// unexpected error
			return fmt.Errorf("creating lock file: %v", err)
		}

		// lock file already exists

		var meta lockMeta
		f, err := os.Open(filename)
		if err == nil {
			err2 := json.NewDecoder(f).Decode(&meta)
			f.Close()
			if errors.Is(err2, io.EOF) {
				emptyCount++
				if emptyCount < 8 {
					// wait for brief time and retry; could be that the file is in the process
					// of being written or updated (which involves truncating) - see issue #232
					select {
					case <-time.After(250 * time.Millisecond):
					case <-ctx.Done():
						return ctx.Err()
					}
					continue
				} else {
					// lockfile is empty or truncated multiple times; I *think* we can assume
					// the previous acquirer either crashed or had some sort of failure that
					// caused them to be unable to fully acquire or retain the lock, therefore
					// we should treat it as if the lockfile did not exist
					log.Printf("[INFO][%s] %s: Empty lockfile (%v) - likely previous process crashed or storage medium failure; treating as stale", s, filename, err2)
				}
			} else if err2 != nil {
				return fmt.Errorf("decoding lockfile contents: %w", err2)
			}
		}

		switch {
		case os.IsNotExist(err):
			// must have just been removed; try again to create it
			continue

		case err != nil:
			// unexpected error
			return fmt.Errorf("accessing lock file: %v", err)

		case fileLockIsStale(meta):
			// lock file is stale - delete it and try again to obtain lock
			// (NOTE: locking becomes imperfect if lock files are stale; known solutions
			// either have potential to cause infinite loops, as in caddyserver/caddy#4448,
			// or must give up on perfect mutual exclusivity; however, these cases are rare,
			// so we prefer the simpler solution that avoids infinite loops)
			log.Printf("[INFO][%s] Lock for '%s' is stale (created: %s, last update: %s); removing then retrying: %s",
				s, name, meta.Created, meta.Updated, filename)
			if err = os.Remove(filename); err != nil { // hopefully we can replace the lock file quickly!
				if !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("unable to delete stale lockfile; deadlocked: %w", err)
				}
			}
			continue

		default:
			// lockfile exists and is not stale;
			// just wait a moment and try again,
			// or return if context cancelled
			select {
			case <-time.After(fileLockPollInterval):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// Unlock releases the lock for name.
func (s *FileStorage) Unlock(_ context.Context, name string) error {
	return os.Remove(s.lockFilename(name))
}

func (s *FileStorage) String() string {
	return "FileStorage:" + s.Path
}

func (s *FileStorage) lockFilename(name string) string {
	return filepath.Join(s.lockDir(), StorageKeys.Safe(name)+".lock")
}

func (s *FileStorage) lockDir() string {
	return filepath.Join(s.Path, "locks")
}

func fileLockIsStale(meta lockMeta) bool {
	ref := meta.Updated
	if ref.IsZero() {
		ref = meta.Created
	}
	// since updates are exactly every lockFreshnessInterval,
	// add a grace period for the actual file read+write to
	// take place
	return time.Since(ref) > lockFreshnessInterval*2
}

// createLockfile atomically creates the lockfile
// identified by filename. A successfully created
// lockfile should be removed with removeLockfile.
func createLockfile(filename string) error {
	err := atomicallyCreateFile(filename, true)
	if err != nil {
		return err
	}

	go keepLockfileFresh(filename)

	return nil
}

// keepLockfileFresh continuously updates the lock file
// at filename with the current timestamp. It stops
// when the file disappears (happy path = lock released),
// or when there is an error at any point. Since it polls
// every lockFreshnessInterval, this function might
// not terminate until up to lockFreshnessInterval after
// the lock is released.
func keepLockfileFresh(filename string) {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, stackTraceBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("panic: active locking: %v\n%s", err, buf)
		}
	}()

	for {
		time.Sleep(lockFreshnessInterval)
		done, err := updateLockfileFreshness(filename)
		if err != nil {
			log.Printf("[ERROR] Keeping lock file fresh: %v - terminating lock maintenance (lockfile: %s)", err, filename)
			return
		}
		if done {
			return
		}
	}
}

// updateLockfileFreshness updates the lock file at filename
// with the current timestamp. It returns true if the parent
// loop can terminate (i.e. no more need to update the lock).
func updateLockfileFreshness(filename string) (bool, error) {
	f, err := os.OpenFile(filename, os.O_RDWR, 0644)
	if os.IsNotExist(err) {
		return true, nil // lock released
	}
	if err != nil {
		return true, err
	}
	defer f.Close()

	// read contents
	metaBytes, err := io.ReadAll(io.LimitReader(f, 2048))
	if err != nil {
		return true, err
	}
	var meta lockMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		// see issue #232: this can error if the file is empty,
		// which happens sometimes when the disk is REALLY slow
		return true, err
	}

	// truncate file and reset I/O offset to beginning
	if err := f.Truncate(0); err != nil {
		return true, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return true, err
	}

	// write updated timestamp
	meta.Updated = time.Now()
	if err = json.NewEncoder(f).Encode(meta); err != nil {
		return false, err
	}

	// sync to device; we suspect that sometimes file systems
	// (particularly AWS EFS) don't do this on their own,
	// leaving the file empty when we close it; see
	// https://github.com/caddyserver/caddy/issues/3954
	return false, f.Sync()
}

// atomicallyCreateFile atomically creates the file
// identified by filename if it doesn't already exist.
func atomicallyCreateFile(filename string, writeLockInfo bool) error {
	// no need to check this error, we only really care about the file creation error
	_ = os.MkdirAll(filepath.Dir(filename), 0700)
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if writeLockInfo {
		now := time.Now()
		meta := lockMeta{
			Created: now,
			Updated: now,
		}
		if err := json.NewEncoder(f).Encode(meta); err != nil {
			return err
		}
		// see https://github.com/caddyserver/caddy/issues/3954
		if err := f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// homeDir returns the best guess of the current user's home
// directory from environment variables. If unknown, "." (the
// current directory) is returned instead.
func homeDir() string {
	home := os.Getenv("HOME")
	if home == "" && runtime.GOOS == "windows" {
		drive := os.Getenv("HOMEDRIVE")
		path := os.Getenv("HOMEPATH")
		home = drive + path
		if drive == "" || path == "" {
			home = os.Getenv("USERPROFILE")
		}
	}
	if home == "" {
		home = "."
	}
	return home
}

func dataDir() string {
	baseDir := filepath.Join(homeDir(), ".local", "share")
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		baseDir = xdgData
	}
	return filepath.Join(baseDir, "certmagic")
}

// lockMeta is written into a lock file.
type lockMeta struct {
	Created time.Time `json:"created,omitempty"`
	Updated time.Time `json:"updated,omitempty"`
}

// lockFreshnessInterval is how often to update
// a lock's timestamp. Locks with a timestamp
// more than this duration in the past (plus a
// grace period for latency) can be considered
// stale.
const lockFreshnessInterval = 5 * time.Second

// fileLockPollInterval is how frequently
// to check the existence of a lock file
const fileLockPollInterval = 1 * time.Second

// Interface guard
var _ Storage = (*FileStorage)(nil)
