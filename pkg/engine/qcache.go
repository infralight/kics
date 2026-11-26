package engine

// Compiled-query cache for long-lived processes (kics serve).
//
// Stock KICS compiles every query, each with its own copy of the common and platform libraries,
// on every scan. WarmShared compiles the libraries and all stock queries once into one compiler
// (each query moved from `package Cx` to its own package) and LoadQuery then reuses prepared queries.
// Custom queries are never added to the shared compiler, so a bad rule fails
// alone as before; they are compiled on first use and kept in a bounded LRU.
// Without WarmShared (the CLI), LoadQuery behaves exactly as upstream.

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/Checkmarx/kics/v2/pkg/engine/source"
	"github.com/Checkmarx/kics/v2/pkg/model"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// DefaultCustomQueryCacheSize caps compiled custom queries (~1-2 MB each: they carry their own libraries).
const DefaultCustomQueryCacheSize = 256

type sharedQueries struct {
	compiler *ast.Compiler
	store    storage.Store
	pkgOf    map[string]string // query key -> package name in the shared compiler

	mu       sync.Mutex
	prepared map[string]*compiled
	custom   *lru
}

type compiled struct {
	once sync.Once
	q    rego.PreparedEvalQuery
	err  error
}

var (
	sharedMu sync.RWMutex
	shared   *sharedQueries
)

func queryKey(common, platform, inputData, content string) string {
	h := sha256.New()
	for _, p := range []string{common, platform, inputData, content} {
		fmt.Fprintf(h, "%d:", len(p))
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mergedInputData(q *model.QueryMetadata, common, platform source.RegoLibraries) string {
	// the same merge as LoadQuery
	d, _ := source.MergeInputData(platform.LibraryInputData, q.InputData)
	d, _ = source.MergeInputData(common.LibraryInputData, d)
	return d
}

// WarmShared compiles libraries + stock queries once and enables the cache for this process.
// It fails (and leaves the cache off) unless every query compiled, so a bad build cannot
// silently run with fewer queries.
func WarmShared(queries []model.QueryMetadata, common, platform source.RegoLibraries, customCacheSize int) (int, error) {
	if len(queries) == 0 {
		return 0, fmt.Errorf("no stock queries")
	}
	data := mergedInputData(&queries[0], common, platform)
	mods := map[string]*ast.Module{}
	pkgOf := map[string]string{}
	var err error
	if mods["Common"], err = ast.ParseModule("Common", common.LibraryCode); err != nil {
		return 0, err
	}
	if mods["Generic"], err = ast.ParseModule("Generic", platform.LibraryCode); err != nil {
		return 0, err
	}
	for i := range queries {
		q := &queries[i]
		if mergedInputData(q, common, platform) != data {
			return 0, fmt.Errorf("query %s brings its own input data; not supported by the shared compiler", q.Query)
		}
		// q.Query is the directory name and repeats across clouds, so packages are numbered
		pkg := fmt.Sprintf("Cx_%d", i)
		m, perr := ast.ParseModule(pkg, q.Content)
		if perr != nil {
			return 0, fmt.Errorf("query %s: %w", q.Query, perr)
		}
		m.Package.Path = ast.Ref{ast.DefaultRootDocument, ast.StringTerm(pkg)}
		mods[pkg] = m
		pkgOf[queryKey(common.LibraryCode, platform.LibraryCode, data, q.Content)] = pkg
	}
	c := ast.NewCompiler().WithUnsafeBuiltins(unsafeRegoFunctions)
	if c.Compile(mods); c.Failed() {
		return 0, c.Errors
	}
	// self-check: every stock query is a distinct module in the compiler
	n := 0
	for _, pkg := range pkgOf {
		if _, ok := c.Modules[pkg]; ok {
			n++
		}
	}
	if n != len(queries) {
		return n, fmt.Errorf("shared compiler self-check: %d of %d stock queries compiled", n, len(queries))
	}
	if customCacheSize <= 0 {
		customCacheSize = DefaultCustomQueryCacheSize
	}
	s := &sharedQueries{
		compiler: c,
		store:    inmem.NewFromReader(bytes.NewBufferString(data)),
		pkgOf:    pkgOf,
		prepared: map[string]*compiled{},
		custom:   newLRU(customCacheSize),
	}
	sharedMu.Lock()
	shared = s
	sharedMu.Unlock()
	return n, nil
}

// loadCached returns a cached prepared query, or ok=false when the cache is off (CLI).
func loadCached(common, platform source.RegoLibraries, inputData string,
	query *model.QueryMetadata) (q *rego.PreparedEvalQuery, ok bool, err error) {
	sharedMu.RLock()
	s := shared
	sharedMu.RUnlock()
	if s == nil {
		return nil, false, nil
	}
	key := queryKey(common.LibraryCode, platform.LibraryCode, inputData, query.Content)
	var e *compiled
	build := func() (rego.PreparedEvalQuery, error) { // custom query: stock compile, kept in the LRU
		return rego.New(
			rego.Query(regoQuery),
			rego.Module("Common", common.LibraryCode),
			rego.Module("Generic", platform.LibraryCode),
			rego.Module(query.Query, query.Content),
			rego.Store(inmem.NewFromReader(bytes.NewBufferString(inputData))),
			rego.UnsafeBuiltins(unsafeRegoFunctions),
		).PrepareForEval(context.Background())
	}
	if pkg, stock := s.pkgOf[key]; stock {
		s.mu.Lock()
		if e = s.prepared[key]; e == nil {
			e = &compiled{}
			s.prepared[key] = e
		}
		s.mu.Unlock()
		build = func() (rego.PreparedEvalQuery, error) {
			return rego.New(
				rego.Query(fmt.Sprintf("result = data.%s.CxPolicy", pkg)),
				rego.Compiler(s.compiler),
				rego.Store(s.store),
				rego.UnsafeBuiltins(unsafeRegoFunctions),
			).PrepareForEval(context.Background())
		}
	} else {
		e = s.custom.get(key)
	}
	// background ctx in build: a cancelled scan must not leave a cached error
	e.once.Do(func() { e.q, e.err = build() })
	if e.err != nil {
		return nil, true, e.err
	}
	prepared := e.q // PreparedEvalQuery.Eval is safe for concurrent use
	return &prepared, true, nil
}

// CacheStats reports cached prepared stock queries and custom queries.
func CacheStats() (stock, custom int) {
	sharedMu.RLock()
	s := shared
	sharedMu.RUnlock()
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	stock = len(s.prepared)
	s.mu.Unlock()
	return stock, s.custom.len()
}

// lru is a mutex-guarded LRU of compiled custom queries.
type lru struct {
	mu    sync.Mutex
	cap   int
	order *list.List // front = most recent; values are keys
	items map[string]*lruItem
}

type lruItem struct {
	el *list.Element
	c  *compiled
}

func newLRU(capacity int) *lru {
	return &lru{cap: capacity, order: list.New(), items: map[string]*lruItem{}}
}

func (l *lru) get(key string) *compiled {
	l.mu.Lock()
	defer l.mu.Unlock()
	if it, ok := l.items[key]; ok {
		l.order.MoveToFront(it.el)
		return it.c
	}
	it := &lruItem{el: l.order.PushFront(key), c: &compiled{}}
	l.items[key] = it
	for l.order.Len() > l.cap {
		old := l.order.Back()
		l.order.Remove(old)
		delete(l.items, old.Value.(string))
	}
	return it.c
}

func (l *lru) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items)
}
