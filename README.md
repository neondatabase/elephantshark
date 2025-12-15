<img src="logo.svg" width="297" height="262" alt="Elephantshark logo">

# Elephantshark

**Elephantshark helps monitor, understand and troubleshoot Postgres network traffic: Postgres clients, drivers and ORMs talking to Postgres servers, proxies and poolers** (also: standby servers talking to their primaries and subscriber servers talking to their publishers).

Elephantshark sits between the two parties in a PostgreSQL-protocol exchange, forwarding messages in both directions while parsing and logging them.

### Why not just use Wireshark? 

Ordinarily [Wireshark](https://www.wireshark.org/) is great for this kind of thing, but using Wireshark is difficult if a connection is SSL/TLS-encrypted. [`SSLKEYLOGFILE`](https://wiki.wireshark.org/TLS#tls-decryption) support was [recently merged into libpq](https://www.postgresql.org/message-id/flat/CAOYmi%2B%3D5GyBKpu7bU4D_xkAnYJTj%3DrMzGaUvHO99-DpNG_YKcw%40mail.gmail.com#afc7fbd9fb2d13959cd97acae8ac8532), but it won’t be available in a release version for some time. And not all Postgres connections use libpq.

To get round this, Elephantshark decrypts and re-encrypts a Postgres connection. It then logs and annotates the messages passing through. Or if you prefer to use Wireshark, Elephantshark can enable that by writing keys to an `SSLKEYLOGFILE` instead.

### Postgres and MITM attacks

If your connection goes over a public network and you can use Elephantshark without changing any connection security options, you have an urgent security problem: you’re vulnerable to [MITM attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack). Elephantshark isn’t the cause of the problem, but it can help show it up.

A fully-secure Postgres connection requires at least one of these parameters on the client: `channel_binding=require`, `sslrootcert=system`, `sslmode=verify-full`, or (when issuing certificates via your own certificate authority) `sslmode=verify-ca`. Non-libpq clients and drivers may have other ways to specify these features.

Note that `sslmode=require` is quite widely used but by itself [provides no security against MITM attacks](https://neon.com/blog/postgres-needs-better-connection-security-defaults), because it does nothing to check who’s on the other end of a connection.


## Get started with Elephantshark

On macOS, install Elephantshark via Homebrew tap:

```bash
% brew install neondatabase/elephantshark/elephantshark
```

Or on any platform, simply download [the `elephantshark` script](elephantshark) and run it using Ruby 3.3 or higher (earlier Ruby versions may support some but not all features). It has no dependencies beyond the Ruby standard library.


## Example session

```bash
% elephantshark
#1  listening on 127.0.0.1 port 5432 ...
```

In a second terminal, connect to and query a Neon Postgres database via Elephantshark by (1) appending `.local.neon.build` to the host name and (2) changing `channel_binding=require` to `channel_binding=disable`:

```bash
% psql 'postgresql://neondb_owner:fake_password@ep-crimson-sound-a8nnh11s.eastus2.azure.neon.tech.local.neon.build/neondb?sslmode=require&channel_binding=disable'
psql (17.5 (Homebrew))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off, ALPN: postgresql)
Type "help" for help.

neondb=> SELECT now();
              now              
-------------------------------
 2025-07-02 11:51:01.721628+00
(1 row)

neondb=> \q
%
```

Back in the first terminal, see what bytes got exchanged:

```text
% elephantshark
#1  listening on 127.0.0.1 port 5432 ...
#1  connected at t0 = 2025-07-04 14:28:59 +0100
#2  listening on 127.0.0.1 port 5432 ...
#1  client -> script: "\x00\x00\x00\x08\x04\xd2\x16\x2f" = SSLRequest
#1  script -> client: "S" = SSL supported
#1  TLSv1.3/TLS_AES_256_GCM_SHA384 connection established with client
#1    server name via SNI: ep-crimson-sound-a8nnh11s.eastus2.azure.neon.tech.local.neon.build
#1  client -> script: "\x00\x00\x00\x56" = 86 bytes of startup message "\x00\x03\x00\x00" = protocol version
#1    "user\x00" = key "neondb_owner\x00" = value
#1    "database\x00" = key "neondb\x00" = value
#1    "application_name\x00" = key "psql\x00" = value
#1    "client_encoding\x00" = key "UTF8\x00" = value
#1    "\x00" = end
#1  connecting to Postgres server: ep-crimson-sound-a8nnh11s.eastus2.azure.neon.tech
#1  script -> server: "\x00\x00\x00\x08\x04\xd2\x16\x2f" = SSLRequest
#1  server -> script: "S" = SSL supported
#1  TLSv1.3/TLS_AES_256_GCM_SHA384 connection established with server
#1  forwarding client startup message to server
#1  script -> server: "\x00\x00\x00\x56" = 86 bytes of startup message "\x00\x03\x00\x00" = protocol version
#1    "user\x00" = key "neondb_owner\x00" = value
#1    "database\x00" = key "neondb\x00" = value
#1    "application_name\x00" = key "psql\x00" = value
#1    "client_encoding\x00" = key "UTF8\x00" = value
#1    "\x00" = end
#1  forwarding all later traffic
#1  server -> client: "R" = Authentication "\x00\x00\x00\x2a" = 42 bytes "\x00\x00\x00\x0a" = AuthenticationSASL
#1    "SCRAM-SHA-256-PLUS\x00" = SASL mechanism
#1    "SCRAM-SHA-256\x00" = SASL mechanism
#1    "\x00" = end
#1  ^^ 43 bytes forwarded at +0.61s
#1  client -> server: "p" = SASLInitialResponse "\x00\x00\x00\x36" = 54 bytes
#1    "SCRAM-SHA-256\x00" = selected mechanism "\x00\x00\x00\x20" = 32 bytes follow
#1    "n,,n=,r=fci+VTkzKrO1kJLK0tL7DEQ1" = SCRAM client-first-message
#1  ^^ 55 bytes forwarded at +0.61s
#1  server -> client: "R" = Authentication "\x00\x00\x00\x5c" = 92 bytes "\x00\x00\x00\x0b" = AuthenticationSASLContinue
#1    "r=fci+VTkzKrO1kJLK0tL7DEQ1Urymgg5N9lizsp07o96IuAEP,s=KBGVGRza5gHefnp4OSU8Gw==,i=4096" = SCRAM server-first-message
#1  ^^ 93 bytes forwarded at +0.71s
#1  client -> server: "p" = SASLResponse "\x00\x00\x00\x6c" = 108 bytes
#1    "c=biws,r=fci+VTkzKrO1kJLK0tL7DEQ1Urymgg5N9lizsp07o96IuAEP,p=PTTYe085GzltpFoYDRDnnJZMPxUKE1Ajrryw6XFY74E=" = SCRAM client-final-message
#1  ^^ 109 bytes forwarded at +0.71s
#1  server -> client: "R" = Authentication "\x00\x00\x00\x36" = 54 bytes "\x00\x00\x00\x0c" = AuthenticationSASLFinal
#1    "v=Oj1crnRpVuFmr693/pTL1lf5+sP7rV0eDW6A/kCTCjg=" = SCRAM server-final-message
#1  server -> client: "R" = Authentication "\x00\x00\x00\x08" = 8 bytes "\x00\x00\x00\x00" = AuthenticationOk
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x15" = 21 bytes "is_superuser\x00" = key "off\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x17" = 23 bytes "DateStyle\x00" = key "ISO, MDY\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x17" = 23 bytes "in_hot_standby\x00" = key "off\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x23" = 35 bytes "standard_conforming_strings\x00" = key "on\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x19" = 25 bytes "integer_datetimes\x00" = key "on\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x19" = 25 bytes "server_encoding\x00" = key "UTF8\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x20" = 32 bytes "search_path\x00" = key "\"$user\", public\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x1a" = 26 bytes "application_name\x00" = key "psql\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x26" = 38 bytes "default_transaction_read_only\x00" = key "off\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x27" = 39 bytes "session_authorization\x00" = key "neondb_owner\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x18" = 24 bytes "server_version\x00" = key "17.5\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x1b" = 27 bytes "IntervalStyle\x00" = key "postgres\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x11" = 17 bytes "TimeZone\x00" = key "GMT\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x19" = 25 bytes "client_encoding\x00" = key "UTF8\x00" = value
#1  server -> client: "S" = ParameterStatus "\x00\x00\x00\x1a" = 26 bytes "scram_iterations\x00" = key "4096\x00" = value
#1  server -> client: "K" = BackendKeyData "\x00\x00\x00\x0c" = 12 bytes "\x8c\xa5\xc2\x9a" = process ID "\xfe\xb8\x7d\x87" = secret key
#1  server -> client: "Z" = ReadyForQuery "\x00\x00\x00\x05" = 5 bytes "I" = idle
#1  ^^ 504 bytes forwarded at +1.22s
#1  client -> server: "Q" = Query "\x00\x00\x00\x12" = 18 bytes "SELECT now();\x00" = query
#1  ^^ 19 bytes forwarded at +8.62s
#1  server -> client: "T" = RowDescription "\x00\x00\x00\x1c" = 28 bytes "\x00\x01" = 1 columns follow
#1    "now\x00" = column name "\x00\x00\x00\x00" = table OID: 0 "\x00\x00" = table attrib no: 0 
#1    "\x00\x00\x04\xa0" = type OID: 1184 "\x00\x08" = type length: 8 "\xff\xff\xff\xff" = type modifier: -1 "\x00\x00" = format: text
#1  server -> client: "D" = DataRow "\x00\x00\x00\x27" = 39 bytes "\x00\x01" = 1 columns follow
#1    "\x00\x00\x00\x1d" = 29 bytes "2025-07-04 13:29:08.633783+00" = column value
#1  server -> client: "C" = CommandComplete "\x00\x00\x00\x0d" = 13 bytes "SELECT 1\x00" = command tag
#1  server -> client: "Z" = ReadyForQuery "\x00\x00\x00\x05" = 5 bytes "I" = idle
#1  ^^ 89 bytes forwarded at +8.73s
#1  client -> server: "X" = Terminate "\x00\x00\x00\x04" = 4 bytes
#1  ^^ 5 bytes forwarded at +10.15s
#1  client hung up
#1  connection end
```

(In the terminal, this would be in colour).

## Options

`elephantshark --help` lists available options.

```text
% elephantshark --help
Elephantshark v0.2.1, Postgres network traffic monitor
https://github.com/neondatabase/elephantshark ++ Copyright 2025 Databricks, Inc. ++ License: Apache 2.0

Usage:
elephantshark [options]

--client-... options affect the connection from the client to Elephantshark
--server-... options affect the onward connection from Elephantshark to the server

        --server-host a.b.cd         Use a fixed Postgres server hostname (default: via SNI, or 'localhost')
        --server-delete-suffix .b.cd Delete a suffix from server hostname provided by client (default: .local.neon.build)
        --client-listen-ip ::1|0.0.0.0|etc.
                                     IP on which to listen for client connection (default: 127.0.0.1)
        --client-listen-port nnnn    Port on which to listen for client connection (default: 5432)
        --server-connect-port nnnn   Port on which to connect to server (default: 5432)
        --server-sslmode disable|prefer|require|verify-ca|verify-full
                                     SSL mode for connection to server (default: prefer)
        --server-sslrootcert system|/path/to/cert
                                     Root/CA certificate for connection to server (default: none)
        --server-sslnegotiation mimic|direct|postgres
                                     SSL negotiation style: mimic client, direct or traditional Postgres (default: mimic)
        --[no-]override-auth         Require password auth from client, do SASL/MD5/password auth with server (default: false)
        --server-channel-binding disable|prefer|require
                                     Channel binding policy for SASL connection to server with --override-auth (default: prefer)
        --[no-]redact-passwords      Redact password messages in logs (default: false)
        --send-chunking whole|byte   Chunk size for sending Postgres data (default: whole)
        --client-ssl-cert /path/to/cert
                                     TLS certificate for connection with client (default: generated, self-signed)
        --client-ssl-key /path/to/key
                                     TLS key for connection with client (default: generated)
        --client-cert-sig rsa|ecdsa  Specify RSA or ECDSA signature for generated certificate (default: rsa)
        --[no-]client-deny-ssl       Tell client that SSL is not supported (default: false)
        --[no-]log-certs             Log TLS certificates (default: false)
        --log-forwarded none|raw|annotated
                                     Whether and how to log forwarded traffic (default: annotated)
        --[no-]quit-on-hangup        Exit when first client or server disconnects (default: false)
        --client-sslkeylogfile /path/to/log
                                     Where to append client traffic TLS decryption data (default: nowhere)
        --server-sslkeylogfile /path/to/log
                                     Where to append server traffic TLS decryption data (default: nowhere)
        --[no-]bw                    Force monochrome output even to TTY (default: automatic)
```

What are these options for?


### Getting between your Postgres client and server

#### Remote Postgres, but local Elephantshark and client

In many cases you’ll probably run your Postgres client and Elephantshark on the same machine, with the server on a different machine, as in the example above.

When you connect your Postgres client via Elephantshark over TLS, Elephantshark uses [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication) to find out what server hostname you gave the client. Elephantshark tries to forward the connection on to that same hostname, except that it first strips off the suffix `.local.neon.build` if present.

> `local.neon.build` is set up such that every possible subdomain — `*.local.neon.build`, `*.*.local.neon.build`, etc. — resolves to your local machine, `127.0.0.1`. It's similar to services such as [localtest.me](https://github.com/localtest-dot-me/localtest-dot-me.github.com?tab=readme-ov-file).

In the example, `ep-crimson-sound-a8nnh11s.eastus2.azure.neon.tech.local.neon.build` is just an alias for your local machine, where Elephantshark is running. Elephantshark then turns that hostname back into the real hostname, `ep-crimson-sound-a8nnh11s.eastus2.azure.neon.tech`, for the onward connection.

It’s also possible to:

* Configure Elephantshark to strip a different domain suffix using the option `--server-delete-suffix .abc.xyz`.

* Specify a fixed server hostname, instead of getting it via SNI from the client, using the `--server-host db.blah.xyz` option. This is useful especially for non-TLS client connections, where SNI is unavailable.

#### Everything local: Postgres, Elephantshark and client

If the server is on the same machine as Elephantshark and the client, you’ll want Elephantshark and the Postgres server to listen for connections on different ports.

Use Elephantshark's `--client-listen-port` and `--server-connect-port` options to achieve this. Both `--client-listen-port` and `--server-connect-port` default to the standard Postgres port, `5432`.

So if your server is running on port `5432`, you might have Elephantshark listen on a non-standard port:

```bash
elephantshark --client-listen-port 5433
```

And then connect the client via Elephantshark on that non-standard port:

```bash
psql 'postgresql://me:mypassword@localhost:5433/mydb'
```

### Security: connection from client

By default, Elephantshark generates a minimal, self-signed TLS certificate on the fly, and does nothing to interfere with the authentication process.

If your Postgres client is using `sslrootcert=system`, `sslmode=verify-full` or `sslmode=verify-ca` you’ll need to either:

1. Downgrade that to `sslmode=require` or lower; or 
2. Supply Elephantshark with a TLS certificate that’s trusted according to `sslrootcert`, plus the corresponding private key, using the `--client-ssl-cert` and `--client-ssl-key` options.

If your Postgres client is using `channel_binding=require`, you’ll need to:

1. Downgrade that to `channel_binding=disable`; or
2. Downgrade to `channel_binding=prefer` _and_ use the `--override-auth` option to have Elephantshark perform authorization on the client’s behalf (cleartext, MD5 and SCRAM auth are supported, by requesting the client’s password in cleartext); or
3. Supply Elephantshark with precisely the same certificate and private key the server is using, via the `--client-ssl-cert` and `--client-ssl-key` options.


### Security: connection to server

Elephantshark has `--server-sslmode` and `--server-sslrootcert` options that work the same as the `sslmode` and `sslrootcert` options to `libpq`. To secure the onward connection to a server that has an SSL certificate signed by a public CA, specify `--server-sslrootcert=system`.


### Logging

By default, Elephantshark logs and annotates all Postgres traffic that passes through. This behaviour can be specified explicitly as `--log-forwarded annotated`.

Alternatives are `--log-forwarded raw`, which logs the data without annotation (it just calls Ruby’s `inspect` on the binary string), or `--log-forwarded none`, which prevents most logging. You might use `--log-forwarded none` if you're using Elephantshark to enable the use of Wireshark, for example.

Example log line for `--log-forwarded annotated`:

```text
server -> client: "Z" = ReadyForQuery "\x00\x00\x00\x05" = 5 bytes "I" = idle
```

Equivalent log line for `--log-forwarded raw`:

```text
server -> client: "Z\x00\x00\x00\x05I"
```

Use the `--log-certs` option to log the certificates being used by TLS connections to both client and server.

Use `--redact-passwords` to prevent password messages being logged. When logging annotated messages, only passwords and MD5 hashes themselves are redacted. When logging raw bytes, any message beginning with "p" (which could be a password message) is redacted.

Use `--bw` to suppress colours in TTY output (or `--no-bw` to force colours even for non-TTY output).


### Connection options

The `--client-listen-port` and `--server-connect-port` options determine the ports on which Elephantshark listens and connects. As described above, they both default to `5432`.

The `--client-listen-ip` option determines the IP address Elephantshark binds to when listening for a client connection. The default is `127.0.0.1` (i.e. `localhost` on IPv4). You could also specify, for example, `::1` (`localhost` on IPv6) or `0.0.0.0` or `::` (wildcard addresses on IPv4 and IPv6). Be sure that a local Postgres install is not listening on the same port. In particular, note that if Postgres is listening on `127.0.0.1` then Elephantshark will agree to listen on `0.0.0.0`, but connections to `127.0.0.1` will go to Postgres, not Elephantshark.

The `--server-sslnegotiation direct` option tells Elephantshark to initiate a TLS connection to the server immediately, without first sending an SSLRequest message (this is a [new feature in Postgres 17+](https://www.postgresql.org/docs/current/release-17.html#RELEASE-17-LIBPQ) and saves a network round-trip). Specifying `--server-sslnegotiation postgres` has the opposite effect. The default is `--server-sslnegotiation mimic`, which has Elephantshark do whatever the connecting client did.

The `--server-channel-binding` option determines the approach to channel binding (SCRAM-SHA-256-PLUS) when authenticating with the server via `--override-auth`. Like the related libpq option, it may be set to `disable`, `prefer` (which is the default) or `require`.

The `--client-cert-sig` option specifies the encryption type of the self-signed certificate Elephantshark presents to connecting clients. The default is `--client-cert-sig rsa`, but `--client-cert-sig ecdsa` is also supported.

If the `--send-chunking byte` option is given, all traffic is forwarded one single byte at a time in both directions. This is extremely inefficient, but it can smoke out software that doesn’t correctly buffer its TCP/TLS input. The default is `--send-chunking whole`, which forwards as many complete Postgres messages as are available when new data are received.

The `--quit-on-hangup` option causes the script to exit when the first Postgres connection closes, instead of listening for a new connection.


### Using Wireshark

If you prefer to use Wireshark to analyze your Postgres traffic, you can use the `--client-sslkeylogfile` and/or `--server-sslkeylogfile` options to specify files that will have TLS keys (for either side of the connection) appended for use in decryption.

You could also simply use an unencrypted connection on the client side. Use the `--client-deny-ssl` option to have Elephantshark tell connecting clients that TLS is not supported (while still supporting TLS for the onward connection to the server).

If using Wireshark, you might also want to specify `--log-forwarded none`.


### Notes

* Postgres options refer to SSL rather than TLS for historical reasons. Elephantshark options do so for consistency with Postgres. SSL and TLS can be regarded as wholly synonymous here.
* When reading Postgres protocol messages, you’ll see that most are [TLV-encoded](https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value): they begin with 1 byte for the message’s type and 4 bytes for its length. Note that the 4-byte length value _includes its own length_: for example, it takes the value `4` if no data follows. Length values elsewhere in the protocol typically _do not_ include their own length, however. There is also some apparent inconsistency in whether strings and lists of strings are null-terminated.
* The Postgres protocol has some [helpful documentation](https://www.postgresql.org/docs/current/protocol.html).
* [Elephant sharks](https://en.wikipedia.org/wiki/Australian_ghostshark) do exist, but the name and logo of this project are inspired primarily by the combination of [Slonik the Postgres elephant](https://wiki.postgresql.org/wiki/Logo) and [Wireshark](https://www.wireshark.org/).


### Tests

To run the tests, ensure Ruby, Docker and OpenSSL are on your `PATH`. Then clone this repo and from the root directory:

* Get the `pg` gem: `gem install pg`
* Optionally, create a file `tests/.env` containing `DATABASE_URL="postgresql://..."` which must point to a database with a PKI-signed SSL cert (e.g. on Neon)
* Run `tests/test.sh` — or to see OpenSSL, Docker and Elephantshark output alongside test results, `tests/test.sh --verbose`


### Change log

* 0.1: Initial release
* 0.2: Support for parallel connections (logged as #1, #2, etc.)


### License

Elephantshark is released under the [Apache-2.0 license](LICENSE).
