package db

import "context"

func defaultScopeContext() context.Context {
	return WithScope(context.Background(), Scope{})
}
