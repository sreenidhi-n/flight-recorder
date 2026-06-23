// Package parsers provides log file parsers for the runtime drift detector.
package parsers

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Record is one accepted egress TCP/UDP record from a VPC Flow Log.
type Record struct {
	SrcAddr string
	DstAddr string // always an IP address
	DstPort int
	Protocol int // 6=TCP, 17=UDP
	Action   string // "ACCEPT" or "REJECT"
	Start    time.Time
}

// ParseVPCFlow reads VPC Flow Logs from r and returns accepted records with
// public destinations. It handles both default v2 format (no header) and
// custom-format logs that begin with a field-name header line.
//
// Lines that are blank, start with '#', or contain '-' placeholder values are
// skipped. Only ACCEPT records with non-private destination IPs are returned.
func ParseVPCFlow(r io.Reader) ([]Record, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	// Field indices — default v2 layout:
	//   0:version 1:account-id 2:interface-id 3:srcaddr 4:dstaddr
	//   5:srcport 6:dstport    7:protocol     8:packets 9:bytes
	//   10:start  11:end       12:action      13:log-status
	idxDst, idxDstPort, idxProtocol, idxAction, idxStart := 4, 6, 7, 12, 10

	headerParsed := false
	var results []Record

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// Auto-detect custom header: first non-comment line where field[0] == "version"
		// and field[1] == "account-id" (string, not a number).
		if !headerParsed {
			if fields[0] == "version" && len(fields) > 4 {
				// Parse field positions from header
				for i, f := range fields {
					switch f {
					case "dstaddr":
						idxDst = i
					case "dstport":
						idxDstPort = i
					case "protocol":
						idxProtocol = i
					case "action":
						idxAction = i
					case "start":
						idxStart = i
					}
				}
				headerParsed = true
				continue
			}
			headerParsed = true // no header — treat as data immediately
		}

		maxIdx := max(idxDst, idxDstPort, idxProtocol, idxAction, idxStart)
		if len(fields) <= maxIdx {
			continue // truncated line
		}

		// Skip no-data placeholder lines
		if fields[idxDst] == "-" || fields[idxAction] == "-" {
			continue
		}

		action := strings.ToUpper(fields[idxAction])
		if action != "ACCEPT" {
			continue
		}

		dstPort, err := strconv.Atoi(fields[idxDstPort])
		if err != nil || dstPort == 0 {
			continue
		}

		protocol, err := strconv.Atoi(fields[idxProtocol])
		if err != nil {
			continue
		}
		// Only TCP (6) and UDP (17)
		if protocol != 6 && protocol != 17 {
			continue
		}

		dstAddr := fields[idxDst]
		if isPrivateOrSpecial(dstAddr) {
			continue
		}

		var start time.Time
		if ts, err := strconv.ParseInt(fields[idxStart], 10, 64); err == nil {
			start = time.Unix(ts, 0).UTC()
		}

		results = append(results, Record{
			SrcAddr:  safeField(fields, 3),
			DstAddr:  dstAddr,
			DstPort:  dstPort,
			Protocol: protocol,
			Action:   action,
			Start:    start,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("vpcflow: scan: %w", err)
	}
	return results, nil
}

func max(vals ...int) int {
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func safeField(fields []string, i int) string {
	if i < len(fields) {
		return fields[i]
	}
	return ""
}

// isPrivateOrSpecial returns true for RFC-1918, loopback, link-local, and
// other non-routable IP ranges that are not useful as egress destinations.
func isPrivateOrSpecial(ip string) bool {
	// Quick prefix checks — avoids full net.ParseIP overhead on hot path.
	prefixes := []string{
		"10.",
		"192.168.",
		"127.",
		"::1",
		"169.254.",
		"224.", "225.", "226.", "227.", "228.", "229.",
		"230.", "231.", "232.", "233.", "234.", "235.",
		"236.", "237.", "238.", "239.",
		"255.",
		"0.",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	// 172.16.0.0/12
	if strings.HasPrefix(ip, "172.") {
		parts := strings.SplitN(ip, ".", 3)
		if len(parts) >= 2 {
			if second, err := strconv.Atoi(parts[1]); err == nil {
				if second >= 16 && second <= 31 {
					return true
				}
			}
		}
	}
	return false
}
