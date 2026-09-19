# Protocol Analyzer — FTP / SFTP / FTPS / TFTP

**Aplikace pro analýzu komunikace protokolů pro přenos souborů**

A server-side application for demonstrating and analyzing file-transfer
protocol communication. Built entirely in Rust, UI with
[Dioxus](https://dioxuslabs.com/).

## Scope

This repository is developed in two stages:

- **Semester project (current)** — **server only**, for all four protocols.
  Each server is standalone and interoperates with existing clients
  (FileZilla, `curl`, `ftp`, `sftp`, `tftp`, etc.) —
  standards-compliant server whose communication can be logged and
  inspected in real time.
- **Bachelor's thesis** — extends this into a full client + server
  application, either as two independently runnable programs or as a single
  app with a split client/server view, so both sides of a session can be
  analyzed side by side.

## What it does (semester project)

On launch, the user picks which **protocol server** to run (FTP, SFTP, FTPS,
or TFTP) and a **port**. Any standard client can connect to it. Every command
and response exchanged with a connecting client — control-channel messages,
and, where relevant, the underlying binary/SSH packets — is displayed and
recorded, so the communication can be inspected and compared across
protocols.

## Supported protocols

| Protocol | Transport      | Implementation                    | Verified against       |
|----------|-----------------|-------------------------------------|--------------------------|
| FTP      | TCP, plaintext  | raw, hand-written                   | FileZilla, `curl`, `ftp` |
| FTPS     | TCP + TLS       | FTP state machine + `rustls`        | FileZilla                |
| TFTP     | UDP             | raw, hand-written                   | `tftp` client, `curl`    |
| SFTP     | SSH2 subsystem  | built on `russh`                    | FileZilla, `sftp`        |

## Project layout

```
crates/
  proto-core/     shared message-log types used by every protocol server
  proto-ftp/      FTP server
  proto-ftps/     FTP server (TLS)
  proto-tftp/     TFTP server
  proto-sftp/     SFTP server
app/              Dioxus desktop app
documentation/    docs, lab exercise
```

## Building

```
cargo build --workspace
cd app/
dx serve
```
