# TODO

## 1. Переписать `yggquic` во внутренний модуль `uu-yggdrasil`

**Статус:** реализовано в `src/quic/`; осталась документация примера
для `yggmail`-подобного сервера.

**Исходник для переноса:**
`/home/u_uu/Documents/o/code/go/ygg/yggquic`

**Зачем:**
нужен QUIC поверх Yggdrasil без TUN для отдельного проекта —
почтового сервера в духе
`/home/u_uu/Documents/o/code/go/ygg/yggmail`.

> Путь к `yggmail`: `/home/u_uu/Documents/o/code/go/ygg/yggmail`

### Что переносим

Go-пакет `yggquic` предоставляет:

- `YggdrasilTransport`, работающий поверх `net.PacketConn` ядра Yggdrasil;
- QUIC-транспорт (`quic-go`) без TUN и без IPv6-сокетов ОС;
- TLS-сертификат, привязанный к ed25519-ключу узла:
  - `CommonName` = hex публичного ключа;
  - самоподписанный сертификат;
  - `InsecureSkipVerify`, но с отдельной проверкой peer certificate;
- проверку, что публичный ключ из сертификата совпадает с адресом
  источника QUIC-пакетов;
- кэш QUIC-соединений по ключу узла;
- повторное использование одного QUIC-соединения для нескольких stream'ов;
- входящие stream'ы через `Accept()`;
- исходящие через `DialContext("yggdrasil", <hex public key>)`;
- защиту от одновременных dial'ов к одному узлу;
- замену старого соединения новым входящим.

### Как встроить в `uu-yggdrasil`

Предлагаемое расположение:

```text
src/quic/mod.rs   публичный API, endpoint, connection cache, accept/dial
src/quic/tls.rs   сертификат и проверка ключа peer'а
```

Фактический API:

```rust
let transport = node.quic()?;
let connection = transport.connect(&peer_key).await?;
let mut stream = connection.open_bi().await?;
stream.write_all(b"...").await?;

// На другой стороне:
let mut transport = node.quic()?;
let mut stream = transport.accept().await?;
let peer = stream.peer_key();
```

- `Yggdrasil::quic()` создаёт endpoint поверх того же `Ironwood`;
- `YggdrasilQuic::connect(&PublicKey)` переиспользует соединение;
- `YggdrasilQuic::accept()` возвращает входящий `QuicStream`;
- `QuicConnection::open_bi()` открывает stream в существующем соединении;
- `QuicStream` реализует `AsyncRead`/`AsyncWrite` и отдаёт ключ пира.

Требования:

- не использовать TUN;
- работать с существующим `Ironwood`/`Yggdrasil` packet API;
- сохранить совместимость с текущими TCP/UDP/inproc API;
- публичный ключ peer'а должен быть доступен приложению;
- ошибки — через `std::io::Error`/собственный `thiserror`-тип, без `panic`;
- не отключать фичи зависимостей и не добавлять `panic = "abort"`;
- проходить `cargo clippy --all-targets --all-features -- -D warnings`.

### Выбор QUIC-крейта

Выбран `quinn` 0.11:

- реализует `AsyncUdpSocket`, поэтому работает поверх `Ironwood`
  без системного UDP-сокета;
- даёт доступ к TLS-сертификату и post-handshake identity;
- поддерживает несколько stream'ов в одном соединении;
- активно сопровождается и имеет совместимую лицензию.

QUIC-адреса синтетические: IPv6-адрес выводится из публичного ключа,
порт фиксирован (`4433`) и не имеет сетевого смысла. Path MTU Discovery
отключён (`may_fragment() == false`), размер датаграмм ограничен буфером
транспорта.

### Этапы

- [x] Изучить `yggquic.go`, `yggquic_test.go` и API `yggmail`.
- [x] Проверить, какие операции с пакетами уже доступны через
      `Yggdrasil::node()`/`Ironwood`.
- [x] Выбрать QUIC-крейт и зафиксировать решение в этом файле.
- [x] Сделать адаптер `AsyncDatagram`/`PacketConn` поверх Yggdrasil.
- [x] Реализовать TLS-сертификат из ed25519-ключа узла.
- [x] Реализовать проверку peer key против source key пакетов.
- [x] Реализовать connection cache, accept loop и stream accept loop.
- [x] Реализовать `connect` с защитой от параллельных dial'ов.
- [x] Добавить unit-тесты с двумя узлами в одном процессе.
- [x] Добавить интеграционный тест QUIC echo/stream между двумя узлами.
- [x] Проверить сценарий в network namespaces без root/sudo.
- [ ] Задокументировать пример использования для `yggmail`-подобного сервера.

### Критерии готовности

- два узла устанавливают QUIC-соединение по публичному ключу;
- несколько stream'ов идут через одно соединение;
- входящий и исходящий трафик сообщает корректный публичный ключ peer'а;
- подмена сертификата/ключа отклоняется;
- нет TUN и root-прав;
- тесты и clippy зелёные.

---

## 2. Текущие задачи по `uu-yggdrasil`

- [x] RTT по каждому `SigReq`, а не по соединению.
- [x] Публичный ключ источника для inproc TCP:
      `YggTcpListener::accept_with_key`, `YggTcpStream::peer_key`.
- [x] Публичный ключ источника для inproc UDP:
      `YggUdpSocket::recv_from_key`.
- [x] Rootless-сценарии в `misc/`:
      `run-twolink-test` и `run-schannel-netns`.
- [x] Проверить сценарии через `unshare -Urnm`, без sudo.
- [x] Зафиксировать ограничение: multicast-обнаружение не поддерживается,
      пиры задаются явно через `tcp://...`.

---

## Правила работы

- Не коммитить без отдельного запроса.
- Не удалять и не ломать существующие публичные API без необходимости.
- Сохранять стиль и структуру surrounding code.
