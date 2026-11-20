package kolodht

import "errors"

var (
	// ErrInvalidConfig means a Config field is out of range, here or in kolo-secure or kolo-transport (wrapped too).
	ErrInvalidConfig = errors.New("kolodht: invalid config")
	// ErrInvalidArgument means a nil or zero identity, an IPv6 address, IPv4-mapped included (kolo-dht is IPv4 only), a record that cannot be
	// used, or too many announcements.
	ErrInvalidArgument = errors.New("kolodht: invalid argument")
	// ErrClosed means the node is closed.
	ErrClosed = errors.New("kolodht: closed")
	// ErrNoNodes means no server answered.
	ErrNoNodes = errors.New("kolodht: no server answered")
	// ErrNotStored means no server stored the announcement.
	ErrNotStored = errors.New("kolodht: announcement not stored")
	// ErrUnreachable means no relay led to a connection, or both sides have a random NAT mapping.
	ErrUnreachable = errors.New("kolodht: peer unreachable")
	// ErrTryLater means a punch with a random mapping on one side is over a budget here or at the peer, or this node
	// already runs its attempts toward the peer's host or key.
	ErrTryLater = errors.New("kolodht: try later")
)
