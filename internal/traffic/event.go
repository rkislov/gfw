package traffic

const (
	Group         = 43014
	BatchSize     = 1000
	SeenCounter   = "gfw_traffic_seen"
	LoggedCounter = "gfw_traffic_logged"
)

type Event struct {
	EventID              string  `json:"event_id"`
	Device               string  `json:"device"`
	Boot                 string  `json:"boot"`
	Namespace            string  `json:"namespace"`
	At                   int64   `json:"at_ms"`
	Kind                 string  `json:"kind"`
	FlowID               string  `json:"flow_id"`
	Zone                 uint16  `json:"zone"`
	Source               string  `json:"src"`
	Destination          string  `json:"dst"`
	SourcePort           uint16  `json:"sport"`
	DestinationPort      uint16  `json:"dport"`
	ReplySource          string  `json:"reply_src"`
	ReplyDestination     string  `json:"reply_dst"`
	ReplySourcePort      uint16  `json:"reply_sport"`
	ReplyDestinationPort uint16  `json:"reply_dport"`
	Protocol             uint8   `json:"proto"`
	NAT                  bool    `json:"nat"`
	Bytes                *uint64 `json:"bytes"`
	Packets              *uint64 `json:"packets"`
	ReplyBytes           *uint64 `json:"reply_bytes"`
	ReplyPackets         *uint64 `json:"reply_packets"`
	Rule                 string  `json:"rule"`
	Revision             int64   `json:"revision"`
	Action               string  `json:"action"`
	Direction            string  `json:"direction"`
	In                   uint32  `json:"in_ifindex"`
	Out                  uint32  `json:"out_ifindex"`
}

type Batch struct {
	Cursor int64   `json:"cursor"`
	Events []Event `json:"events"`
}

type Status struct {
	Queued              int     `json:"queued"`
	Oldest              int64   `json:"oldest_ms"`
	Evicted             uint64  `json:"evicted"`
	Lost                uint64  `json:"lost"`
	IncompleteSnapshots uint64  `json:"incomplete_snapshots"`
	RateLimited         *uint64 `json:"rate_limited,omitempty"`
	Conntrack           bool    `json:"conntrack"`
	NFLOG               bool    `json:"nflog"`
	NFLOGConntrack      bool    `json:"nflog_conntrack"`
	Accounting          bool    `json:"accounting"`
	Error               string  `json:"error,omitempty"`
}
