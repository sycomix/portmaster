package network

import (
	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/base/metrics"
	"github.com/safing/portmaster/service/process"
)

var (
	packetHandlingHistogram            *metrics.Histogram
	blockedOutConnCounter              *metrics.Counter
	encryptedAndTunneledOutConnCounter *metrics.Counter
	encryptedOutConnCounter            *metrics.Counter
	tunneledOutConnCounter             *metrics.Counter
	outConnCounter                     *metrics.Counter

	// History metrics
	historyCntTotal   *metrics.Counter
	historyCntBlocked *metrics.Counter
	historyCntAllowed *metrics.Counter

	// Bandwidth metrics
	bandwidthInHistogram  *metrics.Histogram
	bandwidthOutHistogram *metrics.Histogram
	bytesReceivedCounter  *metrics.Counter
	bytesSentCounter      *metrics.Counter
)

func registerMetrics() (err error) {
	// This needed to be moved here, because every packet is now handled by the
	// connection handler worker.
	packetHandlingHistogram, err = metrics.NewHistogram(
		"firewall/handling/duration/seconds",
		nil,
		&metrics.Options{
			Permission:     api.PermitUser,
			ExpertiseLevel: config.ExpertiseLevelExpert,
		})
	if err != nil {
		return err
	}

	_, err = metrics.NewGauge(
		"network/connections/active/total",
		nil,
		func() float64 {
			return float64(conns.active())
		},
		&metrics.Options{
			InternalID:     "active_connections",
			Permission:     api.PermitUser,
			ExpertiseLevel: config.ExpertiseLevelUser,
		})
	if err != nil {
		return err
	}

	connCounterID := "network/connections/total"
	connCounterOpts := &metrics.Options{
		Name:           "Connections",
		Permission:     api.PermitUser,
		ExpertiseLevel: config.ExpertiseLevelUser,
		Persist:        true,
	}

	blockedOutConnCounter, err = metrics.NewCounter(
		connCounterID,
		map[string]string{
			"direction": "out",
			"blocked":   "true",
		},
		&metrics.Options{
			Name:           "Connections",
			InternalID:     "blocked_outgoing_connections",
			Permission:     api.PermitUser,
			ExpertiseLevel: config.ExpertiseLevelUser,
			Persist:        true,
		},
	)
	if err != nil {
		return err
	}

	encryptedAndTunneledOutConnCounter, err = metrics.NewCounter(
		connCounterID,
		map[string]string{
			"direction": "out",
			"encrypted": "true",
			"tunneled":  "true",
		},
		connCounterOpts,
	)
	if err != nil {
		return err
	}

	encryptedOutConnCounter, err = metrics.NewCounter(
		connCounterID,
		map[string]string{
			"direction": "out",
			"encrypted": "true",
		},
		connCounterOpts,
	)
	if err != nil {
		return err
	}

	tunneledOutConnCounter, err = metrics.NewCounter(
		connCounterID,
		map[string]string{
			"direction": "out",
			"tunneled":  "true",
		},
		connCounterOpts,
	)
	if err != nil {
		return err
	}

	outConnCounter, err = metrics.NewCounter(
		connCounterID,
		map[string]string{
			"direction": "out",
		},
		connCounterOpts,
	)
	if err != nil {
		return err
	}

	// History metrics
	historyCntTotal, err = metrics.NewCounter(
		"network/history/connections/total",
		nil,
		&metrics.Options{
			Name:       "Total Historical Connections",
			Permission: api.PermitUser,
		},
	)
	if err != nil {
		return err
	}

	historyCntBlocked, err = metrics.NewCounter(
		"network/history/connections/blocked",
		nil,
		&metrics.Options{
			Name:       "Total Blocked Historical Connections",
			Permission: api.PermitUser,
		},
	)
	if err != nil {
		return err
	}

	historyCntAllowed, err = metrics.NewCounter(
		"network/history/connections/allowed",
		nil,
		&metrics.Options{
			Name:       "Total Allowed Historical Connections",
			Permission: api.PermitUser,
		},
	)
	if err != nil {
		return err
	}

	// Bandwidth metrics
	bandwidthInHistogram, err = metrics.NewHistogram(
		"network/bandwidth/in/bytes_per_sec",
		nil,
		&metrics.Options{
			Name:       "Incoming Bandwidth",
			Permission: api.PermitUser,
		},
	)
	if err != nil {
		return err
	}

	bandwidthOutHistogram, err = metrics.NewHistogram(
		"network/bandwidth/out/bytes_per_sec",
		nil,
		&metrics.Options{
			Name:       "Outgoing Bandwidth",
			Permission: api.PermitUser,
		},
	)
	if err != nil {
		return err
	}

	bytesReceivedCounter, err = metrics.NewCounter(
		"network/bandwidth/bytes_received",
		nil,
		&metrics.Options{
			Name:       "Total Bytes Received",
			Permission: api.PermitUser,
		},
	)
	if err != nil {
		return err
	}

	bytesSentCounter, err = metrics.NewCounter(
		"network/bandwidth/bytes_sent",
		nil,
		&metrics.Options{
			Name:       "Total Bytes Sent",
			Permission: api.PermitUser,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (conn *Connection) addToMetrics() {
	if conn.addedToMetrics {
		return
	}

	// Don't count requests serviced to the network,
	// as we have an incomplete view here.
	if conn.Process() != nil &&
		conn.Process().Pid == process.NetworkHostProcessID {
		return
	}

	// Only count outgoing connections for now.
	if conn.Inbound {
		return
	}

	// Check the verdict.
	switch conn.Verdict { //nolint:exhaustive // Not critical.
	case VerdictBlock, VerdictDrop:
		blockedOutConnCounter.Inc()
		conn.addedToMetrics = true
		return
	case VerdictAccept, VerdictRerouteToTunnel:
		// Continue to next section.
	default:
		// Connection is not counted.
		return
	}

	// Only count successful connections, not DNS requests.
	if conn.Type == DNSRequest {
		return
	}

	// Select counter based on attributes.
	switch {
	case conn.Encrypted && conn.Tunneled:
		encryptedAndTunneledOutConnCounter.Inc()
	case conn.Encrypted:
		encryptedOutConnCounter.Inc()
	case conn.Tunneled:
		tunneledOutConnCounter.Inc()
	default:
		outConnCounter.Inc()
	}
	conn.addedToMetrics = true
}

// updateBandwidthMetrics updates the bandwidth-related metrics for a connection
func (conn *Connection) updateBandwidthMetrics() {
    if !conn.BandwidthEnabled {
        return
    }

    // Update bandwidth histograms
    bandwidthInHistogram.Update(conn.BandwidthIn)
    bandwidthOutHistogram.Update(conn.BandwidthOut)

    // Record total bytes received and sent
    if bytesReceivedCounter != nil {
        bytesReceivedCounter.Add(1) // Increment by 1 unit
    }
    if bytesSentCounter != nil {
        bytesSentCounter.Add(1) // Increment by 1 unit
    }
}
