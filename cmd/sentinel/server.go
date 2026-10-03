package main

import (
	"log"

	"github.com/alminisl/security-bot/internal/audit"
	"github.com/alminisl/security-bot/internal/notify"
	"github.com/alminisl/security-bot/internal/store"
	"github.com/alminisl/security-bot/internal/web"
)

func newServer(st *store.Store, opts audit.Options, lg *log.Logger, fixes bool, sinks []notify.Sink) *web.Server {
	return web.NewServer(st, opts, lg, fixes, sinks)
}
