# Lab 4 — OS & Networking

## Task 1 — Trace a Request End-to-End

### 1.2 Decode (аннотированный вывод из lab4-trace.txt)

**TCP Handshake (IPv6 loopback):**
21:02:32.365133 IP6 ::1.64244 > ::1.8080: Flags [S] → SYN
21:02:32.365207 IP6 ::1.8080 > ::1.64244: Flags [S.] → SYN-ACK
21:02:32.365226 IP6 ::1.64244 > ::1.8080: Flags [.] → ACK

**HTTP Request:**
21:02:32.365257 IP6 ::1.64244 > ::1.8080: Flags [P.], length 174: HTTP: POST /notes HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Content-Length: 39

{"title":"trace me","body":"in flight"}

**HTTP Response:**
21:02:32.366195 IP6 ::1.8080 > ::1.64244: Flags [P.], length 203: HTTP: HTTP/1.1 201 Created
Content-Type: application/json
Date: Tue, 16 Jun 2026 18:02:32 GMT
Content-Length: 90

{"id":6,"title":"trace me","body":"in flight","created_at":"2026-06-16T18:02:32.365618Z"}

**Connection Close:**
21:02:32.366303 IP6 ::1.64244 > ::1.8080: Flags [F.] → FIN от клиента
21:02:32.366364 IP6 ::1.8080 > ::1.64244: Flags [F.] → FIN от сервера
21:02:32.366392 IP6 ::1.64244 > ::1.8080: Flags [.] → ACK на FIN

### 1.3 Debug commands

1. **`lsof -i :8080`** – что слушает?
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
quicknote 57615 abdra 5u IPv6 0x64cd9aef14d389b8 0t0 TCP *:http-alt (LISTEN)

2. **`netstat -rn`** – таблица маршрутизации (ключевые строки):
default 172.20.10.1 UGScg en0
127 127.0.0.1 UCS lo0
127.0.0.1 127.0.0.1 UH lo0

3. **`ping -c 5 localhost`** – достижимость:
PING localhost (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.074 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.129 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.200 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.193 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.219 ms
5 packets transmitted, 5 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.074/0.163/0.219/0.054 ms

4. **`dig +short example.com @1.1.1.1`** – DNS работает:
104.20.23.154
172.66.147.243

5. **`ps aux | grep quicknote`** – процесс запущен:
abdra 57615 0.0 0.1 411336624 4880 s003 S+ 8:57PM 0:00.02 /var/folders/l_/6gc6h_tj3xd_rpxs35jnpq9h0000gn/T/go-build3205065133/b001/exe/quicknotes

### 1.4 502 reflection
При возникновении 502 Bad Gateway я бы проверил в первую очередь:
- Живой ли процесс (`ps`, `lsof`).
- Логи приложения (stdout или `journalctl`).
- Доступность порта (`curl -I http://localhost:8080/health`).
- Не блокирует ли фаервол (`pfctl`/`iptables`).
- DNS-разрешение, если используются внешние хосты.

---

## Task 2 — Outside-In Debugging on a Broken Deploy

### 2.1 Run broken instance
Запущен второй экземпляр на том же порту:
ADDR=:8080 go run . 2>&1 | tee /tmp/qn-broken.log
Ошибка:
listen: listen tcp :8080: bind: address already in use

### 2.2 Outside-in chain

1. **Запущен ли процесс?**  
   `ps -ef | grep quicknotes` → `501 57615 ... /exe/quicknotes`

2. **Слушает ли порт?**  
   `lsof -i :8080` → `quicknote 57615 ... TCP *:8080 (LISTEN)`

3. **Доступен ли хост?**  
   `curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/health` → `200`

4. **Фаервол?**  
   `sudo pfctl -s all 2>/dev/null || echo "pf not active"` → `pf not active`

5. **DNS?**  
   `dig +short localhost` → (пусто, т.к. localhost резолвится через /etc/hosts)

**Решение:** Порт занят первым процессом (PID 57615), поэтому второй не может запуститься.

### 2.3 Repair
Убит первый процесс (`kill 57615`), запущен новый:
ADDR=:8080 go run . &
sleep 1
curl -s http://localhost:8080/health
Результат: `{"notes":6,"status":"ok"}` – сервер работает.

### 2.4 Mini-postmortem (≤200 слов)
Ошибка `bind: address already in use` возникает, когда процесс уже слушает на порту. Это системная проблема, потому что отсутствует проверка занятости порта перед запуском, нет файла блокировки и нет механизма graceful shutdown. Для предотвращения можно использовать systemd с `Restart=on-failure`, проверять порт через `lsof` перед запуском, или использовать случайные порты в тестовой среде.

---

## Bonus — TLS Handshake

### Setup
- Caddy запущен как reverse proxy на `localhost:8443` → `localhost:8080`.
- Захват выполнен через `sudo tcpdump -i lo0 -nn -s 0 -w lab4-tls.pcap 'tcp port 8443'` (36 пакетов).
- Запрос: `curl -vk https://localhost:8443/health`.

### Decode (из вывода curl)
SSL connection using TLSv1.3 / AEAD-CHACHA20-POLY1305-SHA256
Server certificate:
subject: [NONE]
start date: Jun 16 18:15:40 2026 GMT
expire date: Jun 17 06:15:40 2026 GMT
issuer: CN=Caddy Local Authority - ECC Intermediate
- **TLS версия:** 1.3
- **Шифр:** AEAD-CHACHA20-POLY1305-SHA256
- **Сертификат:** самоподписанный от Caddy Local Authority (CN=Caddy Local Authority - ECC Intermediate)

### Почему TLS 1.0/1.1 убиты?
Клиент в ClientHello предлагает только современные версии (TLS 1.2/1.3). Сервер выбирает наивысшую поддерживаемую. TLS 1.0/1.1 не предлагаются, так как они устарели и небезопасны (уязвимости POODLE, BEAST). Этап, который их убивает, — **переговоры о версии в ClientHello/ServerHello**.

### Скриншоты
- ClientHello: ![ClientHello](screenshots/clienthello.png) (если есть)
- ServerHello: ![ServerHello](screenshots/serverhello.png) (если есть)

