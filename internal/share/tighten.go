package share

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"

	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/rules"
)

// NotifyRulesTightened queues one digest mail per owner whose active shares are newly out of line with the
// rules (after vs before) and returns the number of affected shares. Runs in the caller's tx.
func (s *Service) NotifyRulesTightened(ctx context.Context, tx pgx.Tx, before, after rules.Rules) (int, error) {
	dl := !before.ForbidDownload && after.ForbidDownload
	wm := !before.ForceWatermark && after.ForceWatermark
	dom := !slices.Equal(before.DomainBlock, after.DomainBlock) || !slices.Equal(before.DomainAllow, after.DomainAllow)
	if !dl && !wm && !dom {
		return 0, nil
	}
	rows, err := tx.Query(ctx, `SELECT s.id, u.email, s.allow_download, s.watermark,
		COALESCE(array_agg(COALESCE(v.email, r.email)) FILTER (WHERE r.id IS NOT NULL), '{}')
		FROM shares s JOIN users u ON u.id = s.owner_id
		LEFT JOIN share_recipients r ON r.share_id = s.id AND r.revoked_at IS NULL
		LEFT JOIN users v ON v.id = r.vendor_id
		WHERE s.revoked_at IS NULL AND s.expires_at > now()
		GROUP BY s.id, u.email ORDER BY s.created_at, s.id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	byOwner, owners, n := map[string][]string{}, []string(nil), 0
	for rows.Next() {
		var id uuid.UUID
		var owner string
		var allowDL, wmark bool
		var emails []string
		if err := rows.Scan(&id, &owner, &allowDL, &wmark, &emails); err != nil {
			return 0, err
		}
		var why []string
		if dl && allowDL {
			why = append(why, "已禁止下載 / downloads are now forbidden")
		}
		if wm && !wmark {
			why = append(why, "已強制浮水印 / watermark is now required")
		}
		if dom && slices.ContainsFunc(emails, func(e string) bool { return before.DomainAllowed(e) && !after.DomainAllowed(e) }) {
			why = append(why, "收件人網域已不允許 / a recipient domain is no longer allowed")
		}
		if len(why) == 0 {
			continue
		}
		n++
		if _, ok := byOwner[owner]; !ok {
			owners = append(owners, owner)
		}
		byOwner[owner] = append(byOwner[owner], fmt.Sprintf("%s/shares/%s — %s", s.baseURL, id, strings.Join(why, "; ")))
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows.Close()
	for _, o := range owners {
		subj, body := mail.RulesTightened(byOwner[o])
		if err := s.outbox.Enqueue(ctx, tx, mail.Message{To: o, Subject: subj, Body: body}); err != nil {
			return 0, err
		}
	}
	return n, nil
}
