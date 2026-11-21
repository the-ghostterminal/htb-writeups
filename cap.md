# CAP — Hack The Box

> Retired. Easy, Linux.

## Summary

A dashboard that offers a five-second network capture is the whole box. The
capture endpoint takes a number, and an earlier capture belongs to someone else;
reading it exposes a cleartext FTP login. Those credentials are reused for SSH,
and the resulting low-privileged account can run a Python interpreter carrying
`cap_setuid`. Two small mistakes — an object ID with no ownership check, and a
capability on an interpreter — chain to root.

## Enumeration

```
nmap -p- --min-rate 1000 -T4 -oN allports.txt 10.129.x.x
nmap -sCV -p21,22,80 -oN services.txt 10.129.x.x
```

Three ports: `21/tcp` vsftpd 3.0.3, `22/tcp` OpenSSH 8.2p1 on Ubuntu 20.04,
`80/tcp` Gunicorn with the title "Security Dashboard".

The dashboard's own page source listed the useful routes: `/capture`, `/ip` and
`/netstat`. `/capture` redirected to `/data/1` and rendered a Download button
pointing at `/download/1`. Requesting a batch of IDs showed `/download/0` was a
real pcap (about 10 KB) while `/download/1` was an empty 24-byte header and the
later IDs held only a few hundred bytes. The capture numbered zero was someone
else's session.

## Dead ends

- Anonymous FTP was rejected with `530` by all three methods tried: the plain
  client, an explicit `USER anonymous`, and `curl ftp://…`.
- The first capture fetched (`/download/1`) was empty, so the chain looked dead
  until the ID was walked backwards.
- A piped FTP client got stuck at the password prompt and again on a passive
  data connection. `curl` with a private netrc file was the reliable route.

## Foothold

`tshark` on the recovered pcap showed 72 frames, including a complete FTP
session in plain text: a `USER`, a `331` prompt, a `PASS`, and a `230 Login
successful`. The password is deliberately not reproduced here.

The same username and password worked on SSH, giving a shell as that user. This
is the second lesson of the box: credentials recovered from one service are
worth trying on every other service before looking for an exploit.

## Privilege escalation

`sudo -n -l` required a password, so sudo was not the route. Listing file
capabilities was:

```
getcap -r / 2>/dev/null
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

`cap_setuid` on an interpreter is root:

```
python3.8 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

That produced a shell with `uid=0(root)`. Both flags were read from there.
Nothing was published with a flag, hash, password or target address in it.

## What I would do differently

- Walk the capture IDs immediately. The link on the page pointed at an empty
  capture; the useful one was one number lower.
- Go to `getcap -r /` sooner on a Linux box where sudo is blocked. It is a
  one-line check and it ended the box.
- Keep the FTP client interactive or use a tool that handles passive mode. The
  piped attempts wasted more time than the actual enumeration.

## Detections

- An object ID from a web application that returns another user's file is an
  IDOR. Access logs showing one account repeatedly requesting adjacent IDs are
  a better signal than the single successful request.
- Cleartext FTP is the reason the capture was useful. Requiring TLS and
  redacting credentials from diagnostic captures would have broken the chain.
- A Python interpreter holding `cap_setuid` that calls `setuid(0)` and spawns
  `/bin/bash` is a high-confidence process-creation alert. The capability
  itself is the configuration finding: an interpreter rarely needs it.

---

### Publishing checklist

- [x] Machine is retired
- [x] No flags, hashes, or cracked credentials
- [x] No target IPs included
- [x] Written in my own words
