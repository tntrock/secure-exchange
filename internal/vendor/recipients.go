package vendor

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Querier is satisfied by pgx.Tx and *pgxpool.Pool.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Target is a staff member a vendor may upload to.
type Target struct {
	ID          uuid.UUID
	Name, Email string
}

// targetsFrom selects the usable staff/admin accounts ($1 = vendor) that created the vendor or own a share
// that has (or had) the vendor as a recipient. "Usable" mirrors auth.User.Active for staff: not disabled,
// approved, not expired.
const targetsFrom = ` FROM users u
	WHERE u.role IN ('staff','admin') AND NOT u.disabled AND u.approval = 'approved' AND (u.expires_at IS NULL OR u.expires_at > now())
	  AND (u.id = (SELECT created_by FROM users WHERE id = $1 AND role = 'vendor')
	    OR u.id IN (SELECT s.owner_id FROM shares s JOIN share_recipients r ON r.share_id = s.id WHERE r.vendor_id = $1))`

// UploadTargets lists staff/admin users the vendor may upload to: the creator of the vendor account plus the
// owner of every share that has (or had) this vendor as a recipient; disabled users excluded; ordered by name.
func UploadTargets(ctx context.Context, q Querier, vendorID uuid.UUID) ([]Target, error) {
	rows, err := q.Query(ctx, `SELECT u.id, coalesce(nullif(u.display_name,''), u.email) AS name, u.email`+targetsFrom+` ORDER BY name, u.email`, vendorID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Target, error) {
		var t Target
		return t, r.Scan(&t.ID, &t.Name, &t.Email)
	})
}

// CanUploadTo reports whether staffID is one of the vendor's UploadTargets.
func CanUploadTo(ctx context.Context, q Querier, vendorID, staffID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1`+targetsFrom+` AND u.id = $2)`, vendorID, staffID).Scan(&ok)
	return ok, err
}
