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
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Storage is a type that implements a key-value store with
// basic file system (folder path) semantics. Keys use the
// forward slash '/' to separate path components and have no
// leading or trailing slashes.
//
// A "prefix" of a key is defined on a component basis,
// e.g. "a" is a prefix of "a/b" but not "ab/c".
//
// A "file" is a key with a value associated with it.
//
// A "directory" is a key with no value, but which may be
// the prefix of other keys.
//
// Keys passed into Load and Store always have "file" semantics,
// whereas "directories" are only implicit by leading up to the
// file.
//
// The Load, Delete, List, and Stat methods should return
// fs.ErrNotExist if the key does not exist.
//
// Processes running in a cluster should use the same Storage
// value (with the same configuration) in order to share
// certificates and other TLS resources with the cluster.
//
// Implementations of Storage MUST be safe for concurrent use
// and honor context cancellations. Methods should block until
// their operation is complete; that is, Load() should always
// return the value from the last call to Store() for a given
// key, and concurrent calls to Store() should not corrupt a
// file.
//
// For simplicity, this is not a streaming API and is not
// suitable for very large files.
type Storage interface {
	// Locker enables the storage backend to synchronize
	// operational units of work.
	//
	// The use of Locker is NOT employed around every
	// Storage method call (Store, Load, etc), as these
	// should already be thread-safe. Locker is used for
	// high-level jobs or transactions that need
	// synchronization across a cluster; it's a simple
	// distributed lock. For example, CertMagic uses the
	// Locker interface to coordinate the obtaining of
	// certificates.
	Locker

	// Store puts value at key. It creates the key if it does
	// not exist and overwrites any existing value at this key.
	Store(ctx context.Context, key string, value []byte) error

	// Load retrieves the value at key.
	Load(ctx context.Context, key string) ([]byte, error)

	// Delete deletes the named key. If the name is a
	// directory (i.e. prefix of other keys), all keys
	// prefixed by this key should be deleted. An error
	// should be returned only if the key still exists
	// when the method returns.
	Delete(ctx context.Context, key string) error

	// Exists returns true if the key exists either as
	// a directory (prefix to other keys) or a file,
	// and there was no error checking.
	Exists(ctx context.Context, key string) bool

	// List returns all keys in the given path.
	//
	// If recursive is true, non-terminal keys
	// will be enumerated (i.e. "directories"
	// should be walked); otherwise, only keys
	// prefixed exactly by prefix will be listed.
	List(ctx context.Context, path string, recursive bool) ([]string, error)

	// Stat returns information about key.
	Stat(ctx context.Context, key string) (KeyInfo, error)
}

// Locker facilitates synchronization across machines and networks.
// It essentially provides a distributed named-mutex service so
// that multiple consumers can coordinate tasks and share resources.
//
// If possible, a Locker should implement a coordinated distributed
// locking mechanism by generating fencing tokens (see
// https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html).
// This typically requires a central server or consensus algorithm
// However, if that is not feasible, Lockers may implement an
// alternative mechanism that uses timeouts to detect node or network
// failures and avoid deadlocks. For example, the default FileStorage
// writes a timestamp to the lock file every few seconds, and if another
// node acquiring the lock sees that timestamp is too old, it may
// assume the lock is stale.
//
// As not all Locker implementations use fencing tokens, code relying
// upon Locker must be tolerant of some mis-synchronizations but can
// expect them to be rare.
//
// This interface should only be used for coordinating expensive
// operations across nodes in a cluster; not for internal, extremely
// short-lived, or high-contention locks.
type Locker interface {
	// Lock acquires the lock for name, blocking until the lock
	// can be obtained or an error is returned. Only one lock
	// for the given name can exist at a time. A call to Lock for
	// a name which already exists blocks until the named lock
	// is released or becomes stale.
	//
	// If the named lock represents an idempotent operation, callers
	// should always check to make sure the work still needs to be
	// completed after acquiring the lock. You never know if another
	// process already completed the task while you were waiting to
	// acquire it.
	//
	// Implementations should honor context cancellation.
	Lock(ctx context.Context, name string) error

	// Unlock releases named lock. This method must ONLY be called
	// after a successful call to Lock, and only after the critical
	// section is finished, even if it errored or timed out. Unlock
	// cleans up any resources allocated during Lock. Unlock should
	// only return an error if the lock was unable to be released.
	Unlock(ctx context.Context, name string) error
}

// KeyInfo holds information about a key in storage.
// Key and IsTerminal are required; Modified and Size
// are optional if the storage implementation is not
// able to get that information. Setting them will
// make certain operations more consistent or
// predictable, but it is not crucial to basic
// functionality.
type KeyInfo struct {
	Key        string
	Modified   time.Time
	Size       int64
	IsTerminal bool // false for directories (keys that act as prefix for other keys)
}

// storeTx stores all the values or none at all.
func storeTx(ctx context.Context, s Storage, all []keyValue) error {
	for i, kv := range all {
		err := s.Store(ctx, kv.key, kv.value)
		if err != nil {
			for j := i - 1; j >= 0; j-- {
				s.Delete(ctx, all[j].key)
			}
			return err
		}
	}
	return nil
}

// keyValue pairs a key and a value.
type keyValue struct {
	key   string
	value []byte
}

// KeyBuilder provides a namespace for methods that
// build keys and key prefixes, for addressing items
// in a Storage implementation.
type KeyBuilder struct{}

// CertsPrefix returns the storage key prefix for
// the given certificate issuer.
func (keys KeyBuilder) CertsPrefix(issuerKey string) string {
	return path.Join(prefixCerts, keys.Safe(issuerKey))
}

// CertsSitePrefix returns a key prefix for items associated with
// the site given by domain using the given issuer key.
func (keys KeyBuilder) CertsSitePrefix(issuerKey, domain string) string {
	return path.Join(keys.CertsPrefix(issuerKey), keys.Safe(domain))
}

// SiteCert returns the path to the certificate file for domain
// that is associated with the issuer with the given issuerKey.
func (keys KeyBuilder) SiteCert(issuerKey, domain string) string {
	safeDomain := keys.Safe(domain)
	return path.Join(keys.CertsSitePrefix(issuerKey, domain), safeDomain+".crt")
}

// SitePrivateKey returns the path to the private key file for domain
// that is associated with the certificate from the given issuer with
// the given issuerKey.
func (keys KeyBuilder) SitePrivateKey(issuerKey, domain string) string {
	safeDomain := keys.Safe(domain)
	return path.Join(keys.CertsSitePrefix(issuerKey, domain), safeDomain+".key")
}

// SiteMeta returns the path to the metadata file for domain that
// is associated with the certificate from the given issuer with
// the given issuerKey.
func (keys KeyBuilder) SiteMeta(issuerKey, domain string) string {
	safeDomain := keys.Safe(domain)
	return path.Join(keys.CertsSitePrefix(issuerKey, domain), safeDomain+".json")
}

// OCSPStaple returns a key for the OCSP staple associated
// with the given certificate. If you have the PEM bundle
// handy, pass that in to save an extra encoding step.
func (keys KeyBuilder) OCSPStaple(cert *Certificate, pemBundle []byte) string {
	var ocspFileName string
	if len(cert.Names) > 0 {
		firstName := keys.Safe(cert.Names[0])
		ocspFileName = firstName + "-"
	}
	ocspFileName += fastHash(pemBundle)
	return path.Join(prefixOCSP, ocspFileName)
}

// Safe standardizes and sanitizes str for use as
// a single component of a storage key. This method
// is idempotent.
func (keys KeyBuilder) Safe(str string) string {
	str = strings.ToLower(str)
	str = strings.TrimSpace(str)

	// replace a few specific characters
	repl := strings.NewReplacer(
		" ", "_",
		"+", "_plus_",
		"*", "wildcard_",
		":", "-",
		"..", "", // prevent directory traversal (regex allows single dots)
	)
	str = repl.Replace(str)

	// finally remove all non-word characters
	return safeKeyRE.ReplaceAllLiteralString(str, "")
}

// CleanUpOwnLocks immediately cleans up all
// current locks obtained by this process. Since
// this does not cancel the operations that
// the locks are synchronizing, this should be
// called only immediately before process exit.
// Errors are only reported if a logger is given.
func CleanUpOwnLocks(ctx context.Context, logger *zap.Logger) {
	locksMu.Lock()
	defer locksMu.Unlock()
	for lockKey, storage := range locks {
		if err := storage.Unlock(ctx, lockKey); err != nil {
			logger.Error("unable to clean up lock in storage backend",
				zap.Any("storage", storage),
				zap.String("lock_key", lockKey),
				zap.Error(err))
			continue
		}
		delete(locks, lockKey)
	}
}

func acquireLock(ctx context.Context, storage Storage, lockKey string) error {
	err := storage.Lock(ctx, lockKey)
	if err == nil {
		locksMu.Lock()
		locks[lockKey] = storage
		locksMu.Unlock()
	}
	return err
}

func releaseLock(ctx context.Context, storage Storage, lockKey string) error {
	err := storage.Unlock(context.TODO(), lockKey) // TODO: in Go 1.21, use WithoutCancel (see #247)
	if err == nil {
		locksMu.Lock()
		delete(locks, lockKey)
		locksMu.Unlock()
	}
	return err
}

// locks stores a reference to all the current
// locks obtained by this process.
var locks = make(map[string]Storage)
var locksMu sync.Mutex

// StorageKeys provides methods for accessing
// keys and key prefixes for items in a Storage.
// Typically, you will not need to use this
// because accessing storage is abstracted away
// for most cases. Only use this if you need to
// directly access TLS assets in your application.
var StorageKeys KeyBuilder

const (
	prefixCerts = "certificates"
	prefixOCSP  = "ocsp"
)

// safeKeyRE matches any undesirable characters in storage keys.
// Note that this allows dots, so you'll have to strip ".." manually.
var safeKeyRE = regexp.MustCompile(`[^\w@.-]`)

// defaultFileStorage is a convenient, default storage
// implementation using the local file system.
var defaultFileStorage = &FileStorage{Path: dataDir()}
