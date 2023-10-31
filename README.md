# Haproxy ACME-DNS

This tool can be used to manage (generate and renew) certificates using an ACME server (such as Let's Encrypt or ZeroSSL) and export them in the format that haproxy expects.



## Building

Git clone the repository and build using cargo:

```sh
git clone https://git.magnax.ca/magnax/haproxy-acmedns-issuer.git
cd haproxy-acmedns-issuer
cargo build --release
```


## Installation

The binary should be move into a folder on the path, such as `/usr/local/bin` or `/usr/bin`, and marked as executable.


```bash
  cp haproxy-acmedns /usr/local/bin
  chmod +x /usr/local/bin/haproxy-acmedns
```

The default configuration file path is `/etc/haproxy-acmedns/config.hcl`.

### SystemD timer

First, create a service unit for haproxy at `/etc/systemd/system/haproxy-acmedns.service`:

```desktop
[Unit]
Description=Obtains and renews ACME certificates for Haproxy
After=network-online.target rsyslog.service
Wants=network-online.target haproxy-acmedns.timer

[Service]
Type=oneshot
ExecStart=/usr/local/bin/haproxy-acmedns

[Install]
WantedBy=multi-user.target
```

Then create the matching timer unit at `/etc/systemd/system/haproxy-acmedns.timer`

```desktop
[Unit]
Description=Obtains and renews ACME certificates for Haproxy
Requires=haproxy-acmedns.service

[Timer]
Unit=haproxy-acmedns.service
AccuracySec=12h
OnCalendar=Daily

[Install]
WantedBy=timers.target
```

And finally enable the timer:

```sh
systemctl enable --now haproxy-acmedns.timer
```

### cron

Alternatively, `haproxy-acmedns` can be called by cron on a regular schedule
## Configuration

The configuration file uses the Hashicorp Configuration Language ([hcl](https://github.com/hashicorp/hcl)).

```hcl
storage = "/path/to/storage/for/keys/and/certs"

account {
  email = "your_email_address"
  directory = "https://acme-v02.api.letsencrypt.org/directory"
  accept_terms = true
}

certificate "certificate_name" {
  destination = "/path/for/final/certificate"
  # Command is ran after the certificate has been successfully renewed
  command = "systemctl reload haproxy"

  domain "first.domain.name" {
    server = "https://URL.of.acme-dns.server"
    subdomain = "UUID-of-subdomain-from-acme-dns-registration"
    username = "username-from-acme-dns-registration"
    password = "password-from-acme-dns-registration"
  }
  domain "other.domain.on.certificate" {
    server = "https://URL.of.acme-dns.server"
    subdomain = "UUID-of-subdomain-from-acme-dns-registration"
    username = "username-from-acme-dns-registration"
    password = "password-from-acme-dns-registration"
  }
}

certificate "second_certificate_name" {
  destination = "/path/for/second/certificate"

  domain "second.domain.name" {
    server = "https://URL.of.acme-dns.server"
    subdomain = "UUID-of-subdomain-from-acme-dns-registration"
    username = "username-from-acme-dns-registration"
    password = "password-from-acme-dns-registration"
  }
}
```

There is only a single account entry, but the certificate block can be repeated to manage multiple certificates, and each certificate block can have multiple domain entries.
The certificate name must be unique, but is only used internally identify each certificate without relying on the domains. In other words, the certificate name is stable so that domains can be added and removed.
