# Security policy

Please report vulnerabilities privately through GitHub's "Report a vulnerability"
feature on this repository rather than opening a public issue.

LogPit listens on the network. Defaults bind to loopback only; set `http.token`
before exposing the HTTP port (use separate write-only and read-only tokens for log
shippers and viewers), and put it behind a TLS reverse proxy if it
leaves a trusted network. Syslog over UDP and plain TCP is unauthenticated and
unencrypted by nature; for senders outside a trusted network use the TLS listener, with
`syslog.tls_client_ca` to accept only clients holding a certificate you issued.
