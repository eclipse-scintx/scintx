// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import (
	"fmt"
	"sort"
	"sync"
)

// AdapterFactory constructs a ProviderAdapter instance at gateway startup.
type AdapterFactory func() (ProviderAdapter, error)

var (
	adapterFactoriesMu sync.RWMutex
	adapterFactories   = map[string]AdapterFactory{}
)

// RegisterAdapterFactory registers a ProviderAdapter constructor under its slug.
// Extension packages call this from init() so the gateway can discover compiled-in adapters.
func RegisterAdapterFactory(slug string, factory AdapterFactory) {
	adapterFactoriesMu.Lock()
	defer adapterFactoriesMu.Unlock()
	if _, exists := adapterFactories[slug]; exists {
		panic(fmt.Sprintf("provider adapter factory already registered: %s", slug))
	}
	adapterFactories[slug] = factory
}

// LoadAdapters instantiates all registered ProviderAdapter implementations in sorted slug order.
// Unlike the legacy architecture, adapters without credentials are still instantiated and
// registered so their CheckAvailability status ("missing_credentials") is recorded in the
// Aggregate Report (#68, #71, #73).
func LoadAdapters() ([]ProviderAdapter, error) {
	adapterFactoriesMu.RLock()
	defer adapterFactoriesMu.RUnlock()

	slugs := make([]string, 0, len(adapterFactories))
	for slug := range adapterFactories {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)

	adapters := make([]ProviderAdapter, 0, len(slugs))
	for _, slug := range slugs {
		a, err := adapterFactories[slug]()
		if err != nil {
			return nil, fmt.Errorf("adapter factory %q: %w", slug, err)
		}
		adapters = append(adapters, a)
	}
	return adapters, nil
}

// RegisteredAdapterSlugs returns all registered adapter slugs in sorted order.
func RegisteredAdapterSlugs() []string {
	adapterFactoriesMu.RLock()
	defer adapterFactoriesMu.RUnlock()
	slugs := make([]string, 0, len(adapterFactories))
	for slug := range adapterFactories {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	return slugs
}
