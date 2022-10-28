

CTF{[a-zA-Z0-9]+}

Common Vulnerabilities
- broken access control (user id, cors, no access control for service endpoints, proxy)
- ancient https configs, roll your own crypto, unencrypted passwords
- sql injection, xss, extended entities
- frontend security, insecure design
- insecure defaults
- popular secrets: secret, SECRET, admin, defaults copied from docs
- error handler/logging leaks data
- ssrf
# Web

## Potential challs

- Access data: User id in parameter iteraten
- Dev Endpoint -> Obscure url, Proxy Endpoint
- Bad JWT / Cookie encryption
  - Might need to generate own tokens
- Serialization injection
- Leak exception
- Access files
