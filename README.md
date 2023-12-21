## Authentication Server and cryptographic libraries
### WIP: INCOMPLETE AND UNVERIFIED
### Please don't use it, it's only public for some of the library functions and currently exists under a restrictive license to prevent usage

The project provides an authentication server with simple SQLite database for user data persistence and a series of library functions to generate and verify/decrypt these tokens. It provides other structs to manage the encryption keys, but the main AuthManager struct will generate these for you when initialised and provides helper functions to abstract away encryption.
The server uses stateless signed (asymmetric) and optionally encrypted (symmetric) tokens for managing access.
It utilises a read/write token system, with read tokens doubling as refresh tokens during the late stages of their lifetime, these read tokens each have a limited lifetime, can only provide a certain number of refreshes and have hard expiry for any use.
The write tokens are short-lived and require 2FA re-authentication to get a new copy.
The requirements for read/write will be solely down to you during integration.
This server can be used standalone for client-only use cases, but currently the server can be mounted and started within another Rust application, providing an interface for other parts of your program to verify read and write permissions via their tokens, returning their user ID for matching with a separate instance of the user in your own database, you need to handle authorisation yourself.

### Features
- User invite
- User setup
- User login
- User self-service re-auth
- SQLite persistence
- SMTP  

### TODO:
Add write token refresh with flow taking 2FA code
Add rolling encryption keys
Add proper CSP
Redo cookie support (should probably be done at the same time as CSP)