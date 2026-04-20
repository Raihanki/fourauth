package fourauth

import "github.com/Raihanki/fourauth/service"

func (a *Auth) Service() *service.Service {
	return a.service
}
