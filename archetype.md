# Archetype — Hack The Box

> Retired. Easy, Windows.

## Summary

A backup share readable by an anonymous SMB session held a service
configuration file with a plaintext password. That account authenticated to SQL
Server, where `xp_cmdshell` gave command execution as the SQL service user. An
enabled impersonation privilege then turned that account into SYSTEM. Three
small configuration mistakes — guest-readable backups, a plaintext service
password, and excessive privilege on a service account — chain to full control.

## Enumeration

```
nmap -p- --min-rate 3000 -T4 -oN nmap/allports.txt 10.129.x.x
nmap -sCV -p135,139,445,1433,5985 -oN nmap/services.txt 10.129.x.x
smbclient -L //10.129.x.x -N
smbclient //10.129.x.x/backups -N -c 'ls'
```

Windows Server 2019 Standard (build 17763). Ports: 135/139/445 SMB and RPC,
1433 Microsoft SQL Server 2017, 5985 WinRM, 47001 and the RPC ephemeral range.
There was no RDP listener.

A null session worked. `ADMIN$`, `C$`, `IPC$` and a non-standard `backups`
share were visible. SMB signing was enabled but not required. The `backups`
share contained a single `prod.dtsConfig` file, which was readable without
credentials.

## Dead ends

- Plain SQL authentication with the recovered username failed with
  `Login failed for user 'sql_svc'`. Windows authentication was required.
- `xp_cmdshell 'whoami'` produced a syntax error in the Impacket client. Its
  helper takes the command without SQL quotes.
- JuicyPotato with a common Windows 10 CLSID failed on this Server 2019 build
  with `COM -> recv failed with error: 10038`. The upstream project has no CLSID
  list for Server 2019.
- WinRM returned `405` on `/wsman` and gave no foothold on its own.

## Foothold

`prod.dtsConfig` is an SSIS package configuration. Its connection string held
the service account and its password in clear text. The password is
deliberately not reproduced here.

```
mssqlclient.py -windows-auth 'DOMAIN/sql_svc:<password>@10.129.x.x'
enable_xp_cmdshell
xp_cmdshell whoami
```

`xp_cmdshell` returned `domain\sql_svc`. The user flag was read from that
user's desktop. Credentials recovered from one service were tried on every
other open service before looking for an exploit — in this case the same
account was accepted by SQL Server.

## Privilege escalation

`whoami /priv` showed `SeImpersonatePrivilege` **enabled** and
`SeAssignPrimaryTokenPrivilege` disabled. That is enough for a token-impersonation
attack.

GodPotato-NET4 was uploaded through the SQL client's `upload` helper, which
base64-encodes the file, runs `certutil -decode` on the target and verifies the
MD5. Running it with an explicit command interpreter:

```
C:\Users\Public\gp.exe -cmd "cmd.exe /c whoami > C:\Users\Public\pwn.txt"
```

The `-cmd` argument starts a process directly rather than through a shell, so
redirection requires `cmd.exe /c`. The output confirmed `nt authority\system`.
The administrator flag was then read the same way. No flag, hash or password is
included in this writeup.

## What I would do differently

- Check anonymous SMB share access first on any Windows box. The entire chain
  started with a share that should not have been readable.
- Read `whoami /priv` immediately after getting a service-account shell. It
  points straight at the escalation path and saves a failed exploit attempt.
- Check the client's command syntax before fighting the target. The `xp_cmdshell`
  quoting error was a local tool detail, not a box problem.

## Detections

- Anonymous reads of non-system SMB shares, especially a read of a `.dtsConfig`
  or other configuration file, are a strong signal. Guest access to `backups`
  should not exist.
- Enabling `xp_cmdshell` changes `show advanced options` and the configuration
  itself. Alert on the change, then on `sqlservr.exe` spawning `cmd.exe`.
- A service account holding `SeImpersonatePrivilege` that starts an unexpected
  child process is the GodPotato signal. Parent/child telemetry is enough.
- `certutil -decode` writing an executable into a public writable directory is
  a high-confidence dropper alert, verifiable from process creation plus file
  creation events.

---

### Publishing checklist

- [x] Machine is retired
- [x] No flags, hashes, or cracked credentials
- [x] No target IPs included
- [x] Written in my own words
