package vpncred

import (
	"errors"
	"regexp"
)

var (
	ErrSessionGone = errors.New("сеанс изменился или уже завершён")
	sessionUser    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$`)
)

type DisconnectRequest struct {
	ProfileID string  `json:"profile_id"`
	SessionID *uint32 `json:"session_id"`
	User      string  `json:"user"`
}

func (r DisconnectRequest) Valid() bool {
	return IDPattern.MatchString(r.ProfileID) && r.SessionID != nil && sessionUser.MatchString(r.User)
}
