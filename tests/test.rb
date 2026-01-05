require 'pg'
require 'socket'
require 'timeout'
require 'tmpdir'
require 'uri'
require 'open3'
require 'securerandom'

POSTGRES_IMAGE = 'postgres:18'

QUIET = ARGV[0] != "--verbose"
FILTER = ARGV[QUIET ? 0 : 1]
REDIR = QUIET ? '> /dev/null 2>&1' : ''
SPAWN_OPTS = QUIET ? { :err => File::NULL, :out => File::NULL } : {}

Dir.mktmpdir('elephantshark-tests') do |tmpdir|
  TMPDIR = tmpdir
  CA_CFG = File.join(TMPDIR, "ca.cfg")
  CA_CSR = File.join(TMPDIR, "ca.csr")
  CA_KEY = File.join(TMPDIR, "ca.key")
  CA_PEM = File.join(TMPDIR, "ca.pem")
  CLIENT_CFG = File.join(TMPDIR, "client.cfg")
  CLIENT_CSR = File.join(TMPDIR, "client.csr")
  CLIENT_KEY = File.join(TMPDIR, "client.key")
  CLIENT_PEM = File.join(TMPDIR, "client.pem")
  CERTS_VOLUME_NAME = "elephantshark-test-certs-#{SecureRandom.uuid}"

  File.write(CA_CFG, "[v3_ca]\nbasicConstraints=critical,CA:true,pathlen:1\n")
  File.write(CLIENT_CFG, "[dn]\nCN=localhost\n[req]\ndistinguished_name=dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n")

  puts ">> Generating TLS certs in #{TMPDIR} and temporary volume #{CERTS_VOLUME_NAME} ..."
  `openssl req -new -newkey rsa:4096 -nodes -text -out #{CA_CSR} -keyout #{CA_KEY} -subj "/CN=Elephantshark" #{REDIR}
  openssl x509 -req -in #{CA_CSR} -text -days 2 -extfile #{CA_CFG} -extensions v3_ca -signkey #{CA_KEY} -out #{CA_PEM} #{REDIR}
  openssl req -new -nodes -text -out #{CLIENT_CSR} -keyout #{CLIENT_KEY} -subj "/CN=localhost" -config #{CLIENT_CFG} -extensions EXT #{REDIR}
  openssl x509 -req -in #{CLIENT_CSR} -text -days 2 -CA #{CA_PEM} -CAkey #{CA_KEY} -out #{CLIENT_PEM} #{REDIR}
  podman volume create #{CERTS_VOLUME_NAME}
  tar -C #{TMPDIR} -cf - . | podman volume import #{CERTS_VOLUME_NAME} -
  podman run --rm --name elephantshark-postgres-test-perms \
    -v #{CERTS_VOLUME_NAME}:/etc/ssl/pg:z \
    #{POSTGRES_IMAGE} \
    chown -R postgres:postgres /etc/ssl/pg`

  def await_port(port)
    Timeout::timeout(30) do
      begin
        TCPSocket.new('localhost', port).close
      rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
        sleep 0.5
        retry
      end
    end
  end

  def with_postgres(auth_method = 'scram-sha-256', port = 54320, extra = '', ssl = 'on')
    puts ">> Starting #{POSTGRES_IMAGE} container (auth: #{auth_method}, port: #{port}) ..."
    container_pid = spawn("podman run --rm --name elephantshark-postgres-test \
      -p #{port}:5432 \
      -e POSTGRES_USER=frodo \
      -e POSTGRES_PASSWORD=friend \
      -e POSTGRES_HOST_AUTH_METHOD='#{auth_method}' \
      #{auth_method == 'md5' ? '-e POSTGRES_INITDB_ARGS="--auth-local=md5"' : ''} \
      -v #{CERTS_VOLUME_NAME}:/etc/ssl/pg:z \
      #{POSTGRES_IMAGE} \
      -c ssl=#{ssl} \
      -c ssl_cert_file=/etc/ssl/pg/client.pem \
      -c ssl_key_file=/etc/ssl/pg/client.key \
      #{extra}", **SPAWN_OPTS)

    await_port(port)
    sleep 1 # for additional setup tasks to complete
    yield

  ensure
    puts ">> Stopping #{POSTGRES_IMAGE} container ..."
    unless container_pid.nil?
      Process.kill('SIGTERM', container_pid)
      Process.wait(container_pid)
    end
  end

  def with_elephantshark(args = '', listen_port = 54321, connect_port = 54320)
    rescued = false
    _, stdout_stderr, thread = Open3.popen2e("./elephantshark --server-connect-port #{connect_port} --client-listen-port #{listen_port} #{args}")
    await_port(listen_port)
    es_log = ''

    begin
      block_result = yield
    rescue => e
      rescued = true
      es_log += "Rescued error in with_elephantshark: #{e.message}\n"
    end
    
    Process.kill('SIGTERM', thread.pid) if thread.alive?
    thread.join

    es_log += stdout_stderr.read
    stdout_stderr.close

    puts es_log unless QUIET
    [block_result, es_log, rescued]
  end

  def do_test_query(connection_string)
    PG.connect(connection_string) do |conn|
      conn.exec("SELECT 'xyz' AS col") do |result|
        result.each do |row|
          return row == { "col" => "xyz" }
        end
      end
    end
  end

  def do_sleep_query(connection_string, seconds)
    PG.connect(connection_string) do |conn|
      conn.exec("SELECT pg_sleep($1)", [seconds])
    end
  end

  $passes = $fails = 0

  def do_test(desc)
    actually_do = FILTER.nil? || desc.include?(FILTER)
    return unless actually_do
    result = yield
  rescue => err
    result = err
  ensure
    return unless actually_do
    is_err = result.kind_of?(Exception)
    puts result.full_message if is_err

    failed = is_err || !result
    $passes += 1 unless failed
    $fails += 1 if failed

    puts "#{failed ? "\033[31mFAIL" : "\033[32mPASS"}\033[0m  \033[1m#{desc}\033[0m"
  end

  def contains(haystack, needle, expected = true)
    tidy_haystack = haystack.gsub(/^#[0-9]+  /m, '')  # remove connection numbers
    return true if tidy_haystack.include?(needle) == expected
    puts haystack
    puts "-> unexpectedly #{expected ? 'did not contain' : 'contained'}: #{needle}"
    false
  end

  begin
    with_postgres do

      do_test("basic connection") do
        result, _, rescued = with_elephantshark do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result
      end

      do_test("strip .local.neon.build") do
        result, _, rescued = with_elephantshark do
          do_test_query('postgresql://frodo:friend@localhost.local.neon.build:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result
      end

      do_test("strip an alternative suffix") do
        result, _, rescued = with_elephantshark("--server-delete-suffix .localtest.me") do
          do_test_query('postgresql://frodo:friend@localhost.localtest.me:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result
      end

      do_test("specify a fixed host name") do
        result, _, rescued = with_elephantshark("--server-host localhost") do
          do_test_query('postgresql://frodo:friend@imaginary.server.local.neon.build:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result
      end

      do_test("switch the listening port") do
        result, _, rescued = with_elephantshark('', 65432) do
          do_test_query('postgresql://frodo:friend@localhost:65432/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result
      end

      do_test("detect possinle infinite loop when listen and connect host:port are the same") do
        _, es_log, rescued = with_elephantshark('', 54321, 54321) do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        rescued && contains(es_log, "disconnected to avoid possible infinite loop")
      end

      do_test("connecting to server with --server-sslmode=disable succeeds with no SSL") do
        result, es_log, rescued = with_elephantshark("--server-sslmode=disable") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo')
        end
        !rescued && result && contains(es_log, "connection established with server", false)  # part of the TLS connection message
      end

      do_test("connecting to server with --server-sslmode=prefer (the default) succeeds with SSL") do
        result, es_log, rescued = with_elephantshark("--server-sslmode=prefer") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, "connection established with server")  # part of the TLS connection message
      end

      do_test("connecting to server with --server-sslmode=require succeeds with SSL") do
        result, es_log, rescued = with_elephantshark("--server-sslmode=require") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, "connection established with server")
      end

      do_test("connecting to server with --server-sslmode=verify-full fails without --server-sslrootcert") do
        _, es_log, rescued = with_elephantshark("--server-sslmode=verify-full") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        rescued && contains(es_log, 'certificate verify failed')
      end

      do_test("connecting to server with --server-sslmode=verify-full fails with appropriate --server-sslrootcert if host doesn't match") do
        _, es_log, rescued = with_elephantshark("--server-sslmode=verify-full") do
          do_test_query('postgresql://frodo:friend@127.0.0.1:54321/frodo?sslmode=require&channel_binding=disable')
        end
        rescued && contains(es_log, 'certificate verify failed')
      end

      do_test("connecting to server with --server-sslmode=verify-full succeeds with appropriate ---server-sslrootcert") do
        result, _, rescued = with_elephantshark("--server-sslmode=verify-full --server-sslrootcert=#{CA_PEM}") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result
      end

      do_test("connecting to server with --server-sslmode=verify-ca fails without ---server-sslrootcert") do
        _, es_log, rescued = with_elephantshark("--server-sslmode=verify-ca") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        rescued && contains(es_log, 'certificate verify failed')
      end

      do_test("connecting to server with --server-sslmode=verify-ca succeeds with appropriate ---server-sslrootcert") do
        result, _, rescued = with_elephantshark("--server-sslmode=verify-ca --server-sslrootcert=#{CA_PEM}") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result
      end

      do_test("connecting to server with --server-sslmode=verify-ca succeeds with appropriate ---server-sslrootcert even if host doesn't match") do
        result, _, rescued = with_elephantshark("--server-sslmode=verify-ca --server-sslrootcert=#{CA_PEM}") do
          do_test_query('postgresql://frodo:friend@127.0.0.1:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result
      end

      do_test("connecting to server with --server-sslrootcert=system fails without appropriate certificate") do
        _, es_log, rescued = with_elephantshark("--server-sslrootcert=system") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        rescued && contains(es_log, 'certificate verify failed')
      end

      if ENV['DATABASE_URL'].nil?
        puts 'SKIP  cannot test --server-sslrootcert=system without DATABASE_URL env var'
      else
        db_uri = URI.parse(ENV['DATABASE_URL'])
        db_host = db_uri.host
        db_port = db_uri.port || 5432
        db_uri.host = 'localhost'
        db_uri.port = 54321

        do_test("connecting to server with --server-sslrootcert=system succeeds when server has appropriate cert") do
          result, es_log, rescued = with_elephantshark("--server-sslrootcert=system --server-host #{db_host}", 54321, db_port) do
            do_test_query(db_uri.to_s)
          end
          !rescued && result && contains(es_log, 'server -> client: "C" = CommandComplete "\x00\x00\x00\x0d" = 13 bytes "SELECT 1\x00" = command tag')
        end
      end

      do_test("--server-sslnegotiation postgres") do
        result, es_log, rescued = with_elephantshark("--server-sslnegotiation postgres") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, "direct TLSv1.3/TLS_AES_256_GCM_SHA384 connection established with server", false)
      end

      do_test("--server-sslnegotiation direct") do
        result, es_log, rescued = with_elephantshark("--server-sslnegotiation direct") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, "direct TLSv1.3/TLS_AES_256_GCM_SHA384 connection established with server")
      end

      do_test("--server-sslnegotiation mimic, where client uses Postgres SSL negotiation") do
        result, es_log, rescued = with_elephantshark do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable&sslnegotiation=postgres')
        end
        !rescued && result && contains(es_log, "direct TLSv1.3/TLS_AES_256_GCM_SHA384 connection established with server", false)
      end

      do_test("--server-sslnegotiation mimic, where client uses direct SSL connection") do
        result, es_log, rescued = with_elephantshark do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable&sslnegotiation=direct')
        end
        !rescued && result && contains(es_log, "direct TLSv1.3/TLS_AES_256_GCM_SHA384 connection established with server")
      end

      do_test("--override-auth using SCRAM-SHA-256") do
        result, es_log, rescued = with_elephantshark("--override-auth") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, 'now overriding authentication' + "\n" +
                                               'server -> script: "R" = Authentication "\x00\x00\x00\x2a" = 42 bytes "\x00\x00\x00\x0a" = AuthenticationSASL')
      end

      do_test("--override-auth logs password") do
        result, es_log, rescued = with_elephantshark("--override-auth") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, 'client -> script: "p" = PasswordMessage (cleartext) "\x00\x00\x00\x0b" = 11 bytes "friend\x00" = password')
      end

      do_test("--override-auth with --redact-passwords") do
        result, es_log, rescued = with_elephantshark("--override-auth --redact-passwords") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, 'client -> script: "p" = PasswordMessage (cleartext) "\x00\x00\x00\x0b" = 11 bytes [redacted] = password')
      end

      do_test("--override-auth with --redact-passwords and --log-forwarded raw") do
        result, es_log, rescued = with_elephantshark("--override-auth --redact-passwords --log-forwarded raw") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, 'client -> script: [password message redacted]' + "\n" +
                                               'script -> server: [password message redacted]')
      end

      do_test("--override-auth with channel binding") do
        result, es_log, rescued = with_elephantshark("--override-auth") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, 'script -> server: "p" = SASLInitialResponse "\x00\x00\x00\x65" = 101 bytes' + "\n" +
                                               '  "SCRAM-SHA-256-PLUS\x00" = selected mechanism')
      end

      do_test("--override-auth with no channel binding") do
        result, es_log, rescued = with_elephantshark("--override-auth --server-channel-binding=disable") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, 'script -> server: "p" = SASLInitialResponse "\x00\x00\x00\x4b" = 75 bytes' + "\n" +
                                               '  "SCRAM-SHA-256\x00" = selected mechanism')
      end

      do_test("--send-chunking byte") do
        result, es_log, rescued = with_elephantshark("--send-chunking byte") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        # would be nice to actually test byte-by-byte sending here, but for now let's just check log output
        !rescued && result && contains(es_log, 'bytes forwarded one by one at')
      end

      do_test("--client-ssl-cert and --client-ssl-key matching server to enable channel binding") do
        result, es_log, rescued = with_elephantshark("--client-ssl-cert #{CLIENT_PEM} --client-ssl-key #{CLIENT_KEY}") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=require')
        end
        !rescued && result && contains(es_log, 'client -> server: "p" = SASLInitialResponse "\x00\x00\x00\x50" = 80 bytes' + "\n" +
                                               '  "SCRAM-SHA-256-PLUS\x00" = selected mechanism')
      end

      do_test("--log-certs with RSA generated cert") do
        result, es_log, rescued = with_elephantshark("--log-certs") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, '          Subject: CN=Elephantshark' + "\n" +
                                               '          Subject Public Key Info:' + "\n" +
                                               '              Public Key Algorithm: rsaEncryption' + "\n" +
                                               '                  Public-Key: (2048 bit)')
      end

      do_test("--log-certs with ECDSA generated cert") do
        result, es_log, rescued = with_elephantshark("--log-certs --client-cert-sig ecdsa") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, '          Subject: CN=Elephantshark' + "\n" +
                                               '          Subject Public Key Info:' + "\n" +
                                               '              Public Key Algorithm: id-ecPublicKey' + "\n" +
                                               '                  Public-Key: (256 bit)')
      end

      do_test("--client-deny-ssl causes connection error with sslmode=require") do
        _, es_log, rescued = with_elephantshark("--client-deny-ssl") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        rescued && contains(es_log, 'server does not support SSL, but SSL was required')
      end

      do_test("--client-deny-ssl fails when channel binding is offered") do
        _, es_log, rescued = with_elephantshark("--client-deny-ssl") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo')
        end
        rescued && contains(es_log, 'server offered SCRAM-SHA-256-PLUS authentication over a non-SSL connection')
      end

      do_test("--client-deny-ssl succeeds with --override-auth") do
        result, es_log, rescued = with_elephantshark("--client-deny-ssl --override-auth") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo')
        end
        !rescued && result && contains(es_log, 'script -> client: "N" = SSL not supported')
      end

      do_test("annotated logging of forwarded traffic") do
        result, es_log, rescued = with_elephantshark do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, 'server -> client: "Z" = ReadyForQuery "\x00\x00\x00\x05" = 5 bytes "I" = idle')
      end

      do_test("raw logging of forwarded traffic") do
        result, es_log, rescued = with_elephantshark("--log-forwarded raw") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, 'forwarding all later traffic') &&
          contains(es_log, 'server -> client: "Z\x00\x00\x00\x05I"')
      end

      do_test("no logging of forwarded traffic") do
        result, es_log, rescued = with_elephantshark("--log-forwarded none") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && 
          contains(es_log, 'silently forwarding all later traffic') &&
          contains(es_log, 'server -> client: "Z" = ReadyForQuery "\x00\x00\x00\x05" = 5 bytes "I" = idle', false) &&
          contains(es_log, 'server -> client: "Z\x00\x00\x00\x05I"', false)
      end

      do_test("support multiple connections") do
        results = []
        _, _, rescued = with_elephantshark do
          3.times do
            results << do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
          end
        end
        !rescued && results.all?
      end

      do_test("support multiple connections in parallel") do
        results = []
        t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        _, _, rescued = with_elephantshark do
          3.times.map do |i|
            Thread.new do
              results << do_sleep_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable', 2)
            end
          end.each { |thread| thread.join }
        end
        t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        !rescued && results.all? && t1 - t0 < 5  # in serial would be >= 6
      end

      do_test("support only the socket-testing connection with --quit-on-hangup") do
        _, es_log, rescued = with_elephantshark("--quit-on-hangup") do
          # we already connected once to check the socket is open, so this next connection should fail
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        rescued && contains(es_log, 'Connection refused')
      end

      do_test("SSLKEYLOGFILE writing") do
        cslf = File.join(TMPDIR, 'client-sslkeylogfile')
        sslf = File.join(TMPDIR, 'server-sslkeylogfile')
        result, _, rescued = with_elephantshark("--client-sslkeylogfile #{cslf} --server-sslkeylogfile #{sslf}") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        cslf_contents = File.read(cslf)
        sslf_contents = File.read(sslf)
        !rescued && result && contains(cslf_contents, 'SERVER_HANDSHAKE_TRAFFIC_SECRET') && contains(sslf_contents, 'SERVER_HANDSHAKE_TRAFFIC_SECRET')
      end

      do_test("monochrome output") do
        result, es_log, rescued = with_elephantshark("--bw") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, 'script -> client: "S" = SSL supported')
      end

      do_test("colour output") do
        result, es_log, rescued = with_elephantshark("--no-bw") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, "\e[35mscript -> client:\e[0m \"S\"\e[33m = SSL supported\e[0m")
      end

      do_test("DDL query") do
        result, _, rescued = with_elephantshark do
          PG.connect('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable') do |conn|
            conn.exec("CREATE TABLE names (id int4, first_name text, surname text)")
          end
        end
        !rescued && result.cmd_status == "CREATE TABLE"
      end

      do_test("parameterized SELECT query") do
        result, _, rescued = with_elephantshark do
          PG.connect('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable') do |conn|
            conn.exec_params("SELECT $1 AS s, generate_series AS n FROM generate_series(1, 3)", ['hello'])
          end
        end
        !rescued && result.to_a == [{ "s" => "hello", "n" => "1" }, { "s" => "hello", "n" => "2" }, { "s" => "hello", "n" => "3" }]
      end

      do_test("COPY query") do
        result, _, rescued = with_elephantshark do
          PG.connect('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable') do |conn|
            conn.copy_data "COPY names FROM STDIN CSV" do
              conn.put_copy_data "1,Ada,Lovelace\n"
              conn.put_copy_data "2,Marie,Curie\n"
              conn.put_copy_data "3,Rosalind,Franklin\n"
            end
          end
        end
        !rescued && result.cmd_status == "COPY 3"
      end

      do_test("INSERT query") do
        result, _, rescued = with_elephantshark do
          PG.connect('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable') do |conn|
            conn.exec_params("INSERT INTO names VALUES ($1, $2, $3), ($4, $5, $6), ($7, $8, $9)",
                             [4, 'Erlich', 'Bachman', 5, 'Richard', 'Hendricks', 6, 'Monica', 'Hall'])
          end
        end
        !rescued && result.cmd_status == "INSERT 0 3"
      end

    end

    # non-SSL server connection

    with_postgres('scram-sha-256', 54320, '', 'off') do
      do_test("basic connection where server does not offer SSL") do
        result, es_log, rescued = with_elephantshark do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require&channel_binding=disable')
        end
        !rescued && result && contains(es_log, 'continuing without encryption')
      end
    end

    # additional --override-auth tests with different server auth configs

    with_postgres('trust') do
      do_test("trust auth") do
        result, es_log, rescued = with_elephantshark do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require')
        end
        !rescued && result && contains(es_log, 'forwarding all later traffic' + "\n" +
                                               'server -> client: "R" = Authentication "\x00\x00\x00\x08" = 8 bytes "\x00\x00\x00\x00" = AuthenticationOk')
      end

      do_test("--override-auth + trust auth") do
        result, es_log, rescued = with_elephantshark("--override-auth") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require')
        end
        !rescued && result && contains(es_log, 'now overriding authentication' + "\n" +
                                               'server -> script: "R" = Authentication "\x00\x00\x00\x08" = 8 bytes "\x00\x00\x00\x00" = AuthenticationOk')
      end
    end

    with_postgres('password') do
      do_test("cleartext password auth") do
        result, es_log, rescued = with_elephantshark do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require')
        end
        !rescued && result && contains(es_log, 'forwarding all later traffic' + "\n" +
                                               'server -> client: "R" = Authentication "\x00\x00\x00\x08" = 8 bytes "\x00\x00\x00\x03" = AuthenticationCleartextPassword')
      end

      do_test("--redact-passwords + cleartext password auth") do
        result, es_log, rescued = with_elephantshark("--redact-passwords") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require')
        end
        !rescued && result && contains(es_log, 'client -> server: "p" = PasswordMessage (cleartext) "\x00\x00\x00\x0b" = 11 bytes [redacted] = password')
      end

      do_test("--override-auth + cleartext password auth") do
        result, es_log, rescued = with_elephantshark("--override-auth") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require')
        end
        !rescued && result && contains(es_log, 'now overriding authentication' + "\n" +
                                               'server -> script: "R" = Authentication "\x00\x00\x00\x08" = 8 bytes "\x00\x00\x00\x03" = AuthenticationCleartextPassword')
      end

      do_test("--override-auth + --redact-passwords + cleartext password auth") do
        result, es_log, rescued = with_elephantshark("--override-auth --redact-passwords") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require')
        end
        !rescued && result && contains(es_log, 'client -> script: "p" = PasswordMessage (cleartext) "\x00\x00\x00\x0b" = 11 bytes [redacted] = password' + "\n" +
                                               'script -> server: "p" = PasswordMessage (cleartext) "\x00\x00\x00\x0b" = 11 bytes [redacted] = password')
      end
    end

    with_postgres('md5') do
      do_test("MD5 auth") do
        result, es_log, rescued = with_elephantshark do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require')
        end
        !rescued && result && contains(es_log, 'forwarding all later traffic' + "\n" +
                                               'server -> client: "R" = Authentication "\x00\x00\x00\x0c" = 12 bytes "\x00\x00\x00\x05" = AuthenticationMD5Password')
      end

      do_test("--override-auth + MD5 auth") do
        result, es_log, rescued = with_elephantshark("--override-auth") do
          do_test_query('postgresql://frodo:friend@localhost:54321/frodo?sslmode=require')
        end
        !rescued && result && contains(es_log, 'now overriding authentication' + "\n" +
                                               'server -> script: "R" = Authentication "\x00\x00\x00\x0c" = 12 bytes "\x00\x00\x00\x05" = AuthenticationMD5Password')
      end
    end

    # replication

    with_postgres("scram-sha-256\nhost replication all 0.0.0.0/0 scram-sha-256", 54320,
                  "-c wal_level=replica \
                        -c archive_command='/bin/true' \
                        -c archive_mode=on \
                        -c max_wal_senders=3 \
                        -c max_replication_slots=3 \
                        -c hot_standby=on") do

      PG.connect('postgresql://frodo:friend@localhost:54320/frodo') do |conn|
        conn.exec("SELECT * FROM pg_create_physical_replication_slot('replica1');")
        conn.exec("CREATE ROLE replication WITH REPLICATION PASSWORD 'password' LOGIN;")
      end

      do_test("streaming replication") do
        _, es_log, rescued = with_elephantshark("--server-host localhost") do
          container_recv_pid = spawn("podman run --rm --name elephantshark-postgres-walrecv \
            #{POSTGRES_IMAGE} \
            pg_receivewal -S replica1 -D /tmp \
              -d 'postgresql://replication:password@host.containers.internal:54321/frodo?sslmode=require&channel_binding=disable'", **SPAWN_OPTS)
          sleep 2
          Process.kill('SIGTERM', container_recv_pid)
          Process.wait(container_recv_pid)
        end
        !rescued && contains(es_log, 'server -> client: "C" = CommandComplete "\x00\x00\x00\x16" = 22 bytes "START_REPLICATION\x00" = command tag')
      end
    end

    with_postgres("scram-sha-256\nhost replication all 0.0.0.0/0 scram-sha-256", 54320,
                  "-c wal_level=logical \
                   -c max_wal_senders=3 \
                   -c max_replication_slots=3") do

      PG.connect('postgresql://frodo:friend@localhost:54320/frodo') do |conn|
        conn.exec("CREATE TABLE t1 (a int, b text, PRIMARY KEY(a));")
        conn.exec("INSERT INTO t1 (a, b) VALUES (1, 'x'), (2, 'y'), (3, 'z');")
        conn.exec("CREATE PUBLICATION pub1 FOR ALL TABLES;")
        conn.exec("CREATE ROLE replication WITH REPLICATION PASSWORD 'password' LOGIN;")
        conn.exec("SELECT * FROM pg_create_logical_replication_slot('logslot1', 'pgoutput');")
      end

      do_test("logical replication") do
        _, es_log, rescued = with_elephantshark("--server-host localhost") do
          container_recv_pid = spawn("podman run --rm --name elephantshark-postgres-logicalrecv \
            #{POSTGRES_IMAGE} \
            pg_recvlogical --start -S logslot1 -P pgoutput -o proto_version=1 -o publication_names=pub1 -f /dev/null \
              -d 'postgresql://replication:password@host.containers.internal:54321/frodo?sslmode=require&channel_binding=disable'", **SPAWN_OPTS)
          sleep 2
          Process.kill('SIGTERM', container_recv_pid)
          Process.wait(container_recv_pid)
        end
        !rescued && contains(es_log, 'server -> client: "C" = CommandComplete "\x00\x00\x00\x16" = 22 bytes "START_REPLICATION\x00" = command tag')
      end
    end

  ensure
    Process.waitall
    puts "\033[1m#{$passes} passed, #{$fails} failed\033[0m"
    `podman volume rm #{CERTS_VOLUME_NAME}` unless CERTS_VOLUME_NAME.nil?
    exit($fails == 0)
  end
end
