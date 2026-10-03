# vnm p2p — блок загрузки и раздачи торрентов (ТЗ)

Дополнение к `docs/vpn-node-manager-tz.md`. Хостер расторгает договор, когда IP ноды
появляется в рое BitTorrent: правообладатели собирают адреса пиров и шлют абузы. Цель — чтобы
через ноду нельзя было ни скачивать, ни раздавать торрент, каким бы протоколом ни пришёл
клиент (xray, WireGuard/AWG, другие туннели).

## 0. Почему не хватает того, что есть

| Что есть | Что пропускает |
|---|---|
| xray `sniffing` + правило `protocol: bittorrent` → блок | ловит только **открытое** рукопожатие BitTorrent по TCP. Клиенты (qBittorrent, Transmission, uTorrent) шифруют рукопожатие по умолчанию (MSE/PE), основной поток идёт uTP по UDP на случайных портах |
| блок только трекеров | пиры приходят из PEX, кеша клиента, DHT; обмен с ними идёт мимо трекера |
| туннели (WireGuard/AWG и т. п.) | идут мимо xray, там блока нет совсем |

Что берём у готовых решений:
- **nDPI** (ntop) — классификация потоков, включая шифрованный BitTorrent, DHT и uTP, по
  эвристикам. Встраиваем готовый демон **nDPId** (тот же подход у `Case211/remnawave-admin`),
  свой DPI не пишем.
- **Строгие сигнатуры по полям заголовков** (`forestsnet/torrent-blocker`): uTP ST_SYN, DHT,
  UDP-трекер. Наивный префикс uTP `0x41…` ловит TURN/WebRTC — только строгое совпадение полей.
- **Порог «роя»**: торрент-клиент за минуты обращается к десяткам пиров; единичный сигнал —
  не повод банить клиента.

Шифрование MSE не мешает главному: у uTP **заголовок (20 байт) всегда открыт**, и соединение
начинается с пакета ST_SYN строгого формата. Без SYN uTP-соединение с пиром не возникает.

Входящие от пиров доходят: UDP прокси устроен как full-cone — сокет, который прокси открыл
для клиента, принимает пакеты от любого адреса, и рой, узнав адрес ноды, сам стучится в этот
порт (и ещё долго после ухода клиента — в уже закрытый). Поэтому те же сигнатуры проверяются
и на входе с аплинков (§4, `p2p_in`).

## 1. Цель и инварианты

- **P-1.** Исходящий uTP ST_SYN, DHT-сообщение (BEP 5), UDP-трекер (BEP 15) и открытое
  рукопожатие BitTorrent — от процесса ноды или из туннеля — не уходят в аплинк (enforce).
- **P-2.** Поток, который nDPI **определил** (`detected`) как BitTorrent, разрывается не позже
  чем через секунду после вердикта, а новые соединения к тому же пиру отклоняются в течение
  `peer_ttl`.
- **P-3.** Клиент туннеля, набравший ≥ `ban.threshold` торрент-сигналов за `ban.window`,
  отрезается от аплинка на `ban.ttl`.
- **P-4.** Никогда не трогаются: TCP 80/443, UDP 443 (QUIC), порт 53, `exempt`, соединения к
  самой ноде, ответы на входящие. Пиринг из `p2p.allow` (легальные апдейтеры игр) не режется.
- **P-5.** nDPId пассивен: обычный трафик никогда не ждёт DPI. nDPId не установлен, упал или
  отстаёт → работают сигнатуры, egress и guard не затронуты, `doctor` FAIL.
- **P-6.** Режим `observe` считает «было бы отрезано» и ничего не режет. `p2p` независим от
  `mode` (egress) и `guard`.
- **P-7.** Агент не знает о сервисах. В событиях — адреса, порты, сигнатура и вид источника
  (`local` — процесс ноды, `tunnel` — адрес клиента туннеля). Кто из пользователей прокси
  качает — вне `vnm` (§9).

## 2. Конфиг

```yaml
p2p:
  mode: observe               # observe | enforce | off; по умолчанию off
  signatures: [utp_syn, dht, udp_tracker, bt_handshake]
  ndpi:
    enabled: true
    socket: /run/vnm-p2p/ndpid.sock   # свой каталог: /run/vnm закрыт для всех
    exclude_ports: [53, 80, 443, 853]   # не захватываются вовсе (BPF)
    act_on: [detected]        # guessed — только счётчик и событие
    peer_ttl: 10m
  ban:                        # только клиенты туннелей (P-3)
    threshold: 20
    window: 5m
    ttl: 30m
    scope: all                # all | non_web (оставить 80/443/53)
  allow: [p2p_allow]          # списки адресов легального пиринга

lists:
  - name: torrent_trackers    # домены и адреса трекеров, bootstrap-узлы DHT
    trackers: ["url:https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt"]
    domain: [router.bittorrent.com, router.utorrent.com, dht.transmissionbt.com, dht.libtorrent.org]
    checksum: none
    refresh: 24h
    bounds: { min: 20, max: 20000, max_change: 0.5 }
  - name: p2p_allow
    ip: ["file:/etc/vnm/p2p-allow.list"]

policy:
  - lists: [torrent_trackers]
    action: block
```

Валидация:
- `p2p.mode` без раздела `p2p` — `off`.
- `ndpi.exclude_ports` обязан содержать 53, 80, 443 (P-4) — иначе ошибка конфига.
- `ban.threshold` ≥ 5, `ban.window` ≥ 1m, `ban.ttl` ≥ 1m, `peer_ttl` ≥ 1m.
- Новый источник списка `trackers:` — строки вида `udp://host:port/announce`,
  `http(s)://host[:port]/…`; хосты-имена идут в доменный набор, адреса — в адресный.

## 3. Слои

### 3.1. Сигнатуры в ядре

Строгие совпадения по полям, первый пакет потока (`ct state new`), только UDP/TCP к портам
вне P-4. Точный набор полей фиксируется по эталонным захватам (libtorrent/qBittorrent,
libutp/Transmission, uTorrent) и тестам на ложные срабатывания (§8), а не по префиксам.

| Сигнатура | Что совпадает |
|---|---|
| `utp_syn` | UDP, длина ≥ 20, `type/ver` = ST_SYN v1, расширение и поля заголовка по BEP 29 |
| `dht` | UDP, KRPC-сообщение BEP 5: bencode-словарь с ключами запроса/ответа и `id` длиной 20 |
| `udp_tracker` | UDP, connect-запрос BEP 15: 64-битный `protocol_id` 0x41727101980 + action 0, длина 16 |
| `bt_handshake` | TCP, первый пакет с данными: `0x13` + `BitTorrent protocol` |

Сигнатуры по полезной нагрузке задаются через базу `@ih` (начало полезной нагрузки). Её
поддержка проверяется на всех версиях nft из `SupportedOS`; где её нет — `bt_handshake`
выключается, остальное работает (UDP-заголовок фиксированной длины, хватает `@th`).

### 3.2. Трекеры и DHT по доменам

Обычный список с действием `block` в `policy`: резолвер `vnm` кладёт адреса трекеров в
набор, соединения к ним отклоняются. Это вспомогательный слой: он режет поиск пиров, но не
обмен с уже известными (поэтому §3.1 и §3.3).

### 3.3. nDPId

- Отдельный юнит `vnm-ndpid.service`: бинарь nDPId (pinned версия, статически с libnDPI,
  sha256 в репозитории), свой пользователь, `CAP_NET_RAW`, `CPUQuota=30%`, `MemoryMax=128M`,
  `Nice=10`. GPL-3.0 — поставляется отдельным бинарём, не линкуется в `vnm`.
- Захват — libpcap на аплинках и нижних интерфейсах туннелей, фильтр BPF (`-B`):
  `not port 53 and not tcp port 80 and not port 443 and not port 853` плюс `exempt`.
- События — JSON в сокет `ndpi.socket`; агент — единственный потребитель. **Каждый поток-читатель
  nDPId открывает своё соединение** — агент принимает любое их число. Сокет — в своём каталоге
  `0750 root:vnm-ndpid` (подключение к сокету требует права на поиск в каталоге). Пакеты агенту
  не копируются (`max-packets-per-flow-to-send=0`): нужны только вердикты потоков.
- Сообщения nDPId бывают длиннее 4 КиБ (риски потока, анализ): разбор рассчитан на любой размер
  до 99999, а сбой разбора одного соединения закрывает только его — вход от другого процесса не
  может уронить агента.
- Агент читает `detected`, `guessed`, `detection-update`; BitTorrent-семейство (BitTorrent,
  uTP, DHT по номенклатуре nDPI) → по `act_on`:
  - разрыв потока: удаление записи conntrack по 5-кортежу (netlink);
  - пир (удалённый адрес) в набор `p2p_peers` с таймаутом `peer_ttl`;
  - сигнал в счётчик «роя» источника (§3.4).
- Отставание или потеря сокета → переподключение с backoff, `vnm_p2p_ndpi_up 0`, WARN; через
  1 мин — FAIL в `doctor`. На трафик это не влияет (P-5).
- Атрибуция транзита: на аплинке после NAT источник — адрес ноды. Исходный адрес клиента
  туннеля агент берёт из conntrack (оригинальное направление того же потока).

### 3.4. «Рой» и бан клиента туннеля

Сигналы: сработавшая сигнатура (§3.1) и `detected` от nDPId с источником `tunnel`. Агент
держит скользящее окно `ban.window` по адресу источника. ≥ `ban.threshold` → адрес в
`p2p_ban` с таймаутом `ban.ttl`, событие `p2p.ban`. Для источника `local` (процесс прокси)
бана нет — только сброс потока и событие (P-7).

## 4. Ядро

Всё в таблице `inet vnm`, замена одной транзакцией, как у остальной политики.

```
set p2p_peers4 { type ipv4_addr; flags timeout; }
set p2p_peers6 { type ipv6_addr; flags timeout; }
set p2p_ban4   { type ipv4_addr; flags timeout; }
set p2p_ban6   { type ipv6_addr; flags timeout; }

chain p2p_local {                     # процессы ноды (прокси)
	type filter hook output priority -155; policy accept;
	jump p2p
}
chain p2p_tunnel {                    # клиенты туннелей
	type filter hook prerouting priority -155; policy accept;
	iifname @uplinks jump p2p_in
	iifname @uplinks return
	ip saddr @p2p_ban4 counter name p_ban jump p2p_banned
	jump p2p
}
chain p2p_in {                        # пиры из интернета
	ct direction reply return
	ip saddr @exempt4 return
	udp dport { 53, 443 } return
	tcp dport { 53, 80, 443 } return
	ip saddr @p2p_peers4 counter name p_peer drop
	<сигнатуры>    counter name p_<сигнатура> drop
}
chain p2p {
	ct state != new return
	ip daddr @exempt4 return
	ip daddr @l_p2p_allow_4 return
	ip daddr @p2p_peers4 counter name p_peer drop
	udp dport { 53, 443 } return
	tcp dport { 53, 80, 443 } return
	<utp_syn>      counter name p_utp_syn drop
	<dht>          counter name p_dht drop
	<udp_tracker>  counter name p_udp_tracker drop
	<bt_handshake> counter name p_bt_handshake drop
}
```

- **Приоритет −155:** после conntrack (−200) и guard (−160), до классификации egress (−150):
  отрезанный поток не тратит выход WARP.
- `p2p_banned` при `scope: all` — `drop`, при `non_web` — пропускает 53/80/443.
- `observe`: те же правила со счётчиками без `drop`; агент в этом режиме не удаляет conntrack
  и не пополняет `p2p_peers`/`p2p_ban`, только считает.
- `log` — по механике `docs/vpn-node-manager-logging-tz.md` (NFLOG-группа, лимит на правило).

## 5. CLI

- `vnm p2p observe|enforce|off [-auto-rollback 5m] | confirm | rollback` — общий
  переключатель `modeswitch`, как у `egress` и `guard`.
- `vnm p2p status` — режим, состояние nDPId, сбросы по слоям, активные баны и пиры.
- `vnm p2p unban <ip>` — снять бан с клиента туннеля.
- `vnm test <ip>` — строка `p2p: peer blocked until …` / `tunnel client banned until …`.
- `vnm doctor` — nDPId не работает или сокет молчит > 1 мин → FAIL; `p2p` в observe → WARN;
  `bt_handshake` выключен из-за nft без `@ih` → WARN.

## 6. Логи и метрики

- `vnm_p2p_dropped_total{layer,signature}` — `layer`: `signature|peer|ban`.
- `vnm_p2p_ndpi_events_total{proto,verdict}` — `verdict`: `detected|guessed`.
- `vnm_p2p_bans_total`, `vnm_p2p_bans_active`, `vnm_p2p_peers_active`, `vnm_p2p_ndpi_up`,
  `vnm_p2p_mode{mode}`.
- События журнала: `p2p.drop` (сигнатура, адрес и порт назначения, вид источника, адрес
  клиента туннеля), `p2p.ndpi` (протокол, вердикт, 5-кортеж), `p2p.ban`/`p2p.unban`.
  Идентификаторов пользователей нет (P-7).

## 7. Установщик и соседи

- `vnm install` ставит `vnm-ndpid` вместе с агентом; `p2p.mode` остаётся `off`, пока его не
  включили явно.
- xray: правило `protocol: bittorrent` в профилях остаётся — дешёвый первый слой для
  открытого рукопожатия.
- В контейнере (LXC) libpcap и nft работают в своём пространстве имён; захват на нижних
  интерфейсах туннелей — если они есть в контейнере.
- `guard` и `p2p` не пересекаются: guard — входящие из блок-листов, p2p — пиринг в обе
  стороны.

## 8. Тесты

- **Рендер/валидация:** golden-правила в enforce/observe/off; P-4 в `exclude_ports`; разбор
  `trackers:` (udp/http/https, адреса и имена, мусор отвергается).
- **Сигнатуры на стенде (netns):**
  - позитив: uTP ST_SYN, DHT ping/find_node/get_peers, UDP tracker connect, открытое
    рукопожатие — от «процесса ноды» и из «туннеля» → drop, счётчик;
  - негатив (ноль совпадений): STUN binding, TURN ChannelData, WebRTC (DTLS/SRTP), QUIC
    Initial, WireGuard, DNS, NTP, захваты UDP популярных игр и голосовых сервисов.
- **nDPId:** воспроизведение захватов шифрованной сессии qBittorrent (MSE, uTP и TCP) →
  `detected` → conntrack удалён, пир в `p2p_peers`, повтор к пиру отклонён; захваты
  браузера, видео, игр → ни одного `detected` BitTorrent.
- **Рой:** 20 сигналов за окно от адреса туннеля → бан; `local` → бана нет; `unban`.
- **Отказ:** nDPId убит → трафик идёт, сигнатуры режут, `doctor` FAIL.
- **Нагрузка:** 1 vCPU, 500 Мбит/с смешанного трафика — CPU nDPId в пределах квоты, без
  роста задержки установления соединений.
- **Пилот:** одна нода, `observe` сутки → разбор `guessed`/`detected` и сработавших сигнатур
  на ложные → `enforce -auto-rollback 5m` → confirm.

## 9. Вне vnm: кто из пользователей прокси качает

Для `local` агент видит только поток, не пользователя. Атрибуция — по журналу доступа прокси
(пользователь ↔ адрес назначения): события `p2p.drop`/`p2p.ndpi` сопоставляются по адресу и
времени, порог «роя» на пользователя — и уже бэкенд решает: предупредить, отключить,
отключить пиринг. Отдельное ТЗ на стороне управления.

## 10. Этапы

1. ✅ Сигнатуры §3.1: конфиг, планировщик, рендер, `vnm p2p`, статус/метрики/doctor, стенд P-1…P-N5.
   Отложено: источник `trackers:` и список трекеров (§3.2).
2. ✅ `vnm-ndpid`: статическая сборка nDPId 1.7.0 / libnDPI 6.1 (Alpine, libpcap статически),
   юнит, слушатель, `p2pwatch`, наборы `p2p_peers`/`p2p_ban` с таймаутом; сквозной тест
   nDPId → сокет → агент → набор ядра. Пилот на одной ноде в observe.
3. ✅ Входящие от пиров (`p2p_in`): на живой ноде сигнатуры молчали, пока проверялось только
   исходящее, — рой стучался в UDP-порт прокси снаружи. Enforce сигнатур и пиров nDPI на
   двух нодах: торрент-потоки за минуты падают с сотен до единиц, клиенты не задеты.
4. Бан клиентов туннелей в enforce.
5. Атрибуция пользователей прокси (§9, вне vnm).

## 11. Открытые вопросы

- `p2p_in` режет всё входящее от адреса из `p2p_peers` на не-веб-порты: если этот адрес — ещё
  и клиент ноды на нестандартном порту, он отвалится на `peer_ttl`. Сузить до UDP или до
  портов, которые нода не слушает.
- Собственный адрес выхода (WARP) попадает в «клиенты» и считается в бан: исключать адреса
  самой ноды, в том числе на интерфейсах выходов, при каждом обновлении, а не на старте.
- Легальный пиринг: апдейтеры игр и лаунчеры раздают обновления по BitTorrent — откуда брать
  `p2p_allow` (ASN/домены CDN издателей) и нужен ли он с первого дня.
- `guessed` от nDPI: оставить только счётчиком или учитывать в «рое» с меньшим весом.
- IPv6 у сигнатур: те же правила для `ip6`, проверить захваты uTP по IPv6.
- Захват на нижних интерфейсах туннелей против разбора conntrack на аплинке — что дешевле
  на 1 vCPU.
