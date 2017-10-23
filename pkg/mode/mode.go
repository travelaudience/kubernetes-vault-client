package mode

type contextKey int

const (
	Client contextKey = iota
	Token
	Accessor
)
