package auth

import "context"

type ctxKey struct{}

func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// UserFrom returns the user in ctx, or nil.
func UserFrom(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKey{}).(*User)
	return u
}
