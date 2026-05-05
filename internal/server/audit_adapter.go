package server

// storageAuditAdapter bridges storage.Store → audit.Storer.
// Both storage.AuditEvent and audit.AuditEvent are structurally identical;
// they are kept separate to avoid a circular import between the two packages.
// The storage layer recomputes PrevHash and Hash when it receives the event.

import (
	"context"

	"github.com/tass-security/tass/internal/audit"
	"github.com/tass-security/tass/internal/storage"
)

type storageAuditAdapter struct {
	s storage.Store
}

func NewAuditEmitter(s storage.Store) *audit.Emitter {
	return audit.NewEmitter(&storageAuditAdapter{s: s})
}

func (a *storageAuditAdapter) SaveAuditEvent(ctx context.Context, evt audit.AuditEvent) error {
	return a.s.SaveAuditEvent(ctx, storage.AuditEvent{
		ID:         evt.ID,
		Ts:         evt.Ts,
		TenantID:   evt.TenantID,
		ActorGHID:  evt.ActorGHID,
		ActorLogin: evt.ActorLogin,
		Repo:       evt.Repo,
		Action:     string(evt.Action),
		TargetID:   evt.TargetID,
		BeforeJSON: evt.BeforeJSON,
		AfterJSON:  evt.AfterJSON,
		IP:         evt.IP,
		UserAgent:  evt.UserAgent,
		// PrevHash and Hash are computed by storage.SaveAuditEvent
	})
}
