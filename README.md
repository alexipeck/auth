## Authentication Server and cryptographic libraries
### WIP: UNVERIFIED
### If you do decide to use it, be careful how you use it

The project provides an authentication server with simple SQLite database for user data persistence and a series of library functions to generate and verify/decrypt these tokens. It provides other structs to manage the encryption keys, but the main AuthManager struct will generate these for you when initialised and provides helper functions to abstract away encryption/decryption and serialization/deserialization.
The server uses stateless signed (asymmetric) and optionally encrypted (symmetric) tokens for managing access.
It utilises a read/write token system, with read tokens doubling as refresh tokens during the late stages of their lifetime, these read tokens each have a configurable limited lifetime, can only provide a certain number of refreshes and have hard expiry time for any use case.
Login requires email, password and 2FA code at the same time.
The write tokens are short-lived and require 2FA re-authentication to get a new copy.
The requirements for read/write will be solely down to you during integration.
This server can be used standalone for client-only use cases, but the server can be mounted and started within any server-side Rust application, providing an interface for other parts of your program to verify read and write permissions via their tokens, returning their user ID for matching with a separate instance of the user in your own database, you need to handle authorisation yourself. This library is currently placed as an identity provider.

### Features
- User invite
- User setup
- User login (2FA enforced)
- User self-service re-auth
- SQLite persistence
- SMTP
- Tokenization of arbitrary data
- Read/write token mechanism for client authentication
- secure httponly cookies

### TODO:
Add rolling encryption keys
Add proper CSP
Add CSRF
Include JS/TS example login page and shared worker responsible for maintaining tokens across all instances of your web app 
