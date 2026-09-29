---
"@alternatefutures/ac-auth-next": minor
---

Initial release: encrypted httpOnly session cookie (HKDF + A256GCM, __Host- prefix over https), sign-in / callback / sign-out / session route handlers, auth() for server code, a proxy that refreshes with rotation safety and forwards the fresh cookie, and a client AuthProvider over the handlers.
