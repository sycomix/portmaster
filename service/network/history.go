package network

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/safing/portmaster/base/database"
	"github.com/safing/portmaster/base/database/query"
	"github.com/safing/portmaster/base/database/record"
	"github.com/safing/portmaster/base/log"
)

const (
	historyDBKey               = "history:"
	defaultHistoryRetentionDays = 30
)

// HistoryEntry represents a single connection history record
type HistoryEntry struct {
	record.Base
	sync.Mutex

	ID string
	// Connection details
	ProcessName   string
	ProcessPath   string
	Domain        string
	RemoteIP      string
	Protocol      uint8
	Port          uint16
	Verdict       Verdict
	// Timing
	Started       int64
	Ended         int64
	// Traffic stats
	BytesReceived uint64
	BytesSent     uint64
	// Additional metadata
	Internal      bool
	Tunneled      bool
	Encrypted     bool
}

type historyManager struct {
	sync.RWMutex
	db *database.Interface
}

var (
	history *historyManager
)

// InitHistory initializes the connection history system
func InitHistory() error {
	// Register history database
	_, err := database.Register(&database.Database{
		Name:        "history",
		Description: "Network Connection History",
		StorageType: database.StorageTypeInjected,
	})
	if err != nil {
		return fmt.Errorf("failed to register history database: %w", err)
	}

	// Create history manager
	history = &historyManager{
		db: database.NewInterface(&database.Options{
			Local:    true,
			Internal: true,
		}),
	}

	return nil
}

// Save stores a history entry in the database
func (hm *historyManager) Save(entry *HistoryEntry) error {
	// Set key for the entry
	entry.SetKey(fmt.Sprintf("%s%d:%s", historyDBKey, entry.Started, entry.ID))

	// Save using database interface
	return hm.db.PutNew(entry)
}

// Query returns connection history entries matching the given criteria
func (hm *historyManager) Query(from, to int64) ([]*HistoryEntry, error) {
	// Create query for time range
	q := query.New(fmt.Sprintf("%s%d:", historyDBKey, from))

	// Execute query
	it, err := hm.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer it.Cancel()

	var entries []*HistoryEntry
	for r := range it.Next {
		// Skip entries outside our time range
		if r.Key() > fmt.Sprintf("%s%d:", historyDBKey, to) {
			break
		}

		entry, ok := r.(*HistoryEntry)
		if !ok {
			log.Warningf("invalid history entry type: %T", r)
			continue
		}

		entries = append(entries, entry)
	}

	return entries, it.Err()
}

// Cleanup removes history entries older than the retention period
func (hm *historyManager) Cleanup() {
	cutoff := time.Now().AddDate(0, 0, -defaultHistoryRetentionDays)

	// Create context for purge operation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Purge old records
	n, err := hm.db.PurgeOlderThan(ctx, historyDBKey, cutoff)
	if err != nil {
		log.Warningf("failed to purge old history entries: %s", err)
		return
	}

	log.Debugf("cleaned up %d old history entries", n)
}
