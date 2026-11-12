# Стендовая проверка GFW

Скрипты рассчитаны на свежую изолированную Linux-ВМ с правами root. Используются локальные пространства имён, veth и тестовые диапазоны адресов. Нагрузочный скрипт включает IPv4 forwarding и conntrack accounting в гостевой системе. Скрипт авторизации меняет конфигурацию тестового FreeRADIUS и создаёт собственный CA. Для каждого запуска используйте чистую ВМ или её снимок.

Для `auth.py` подготовьте Ubuntu 26.04 arm64 с OpenLDAP, FreeRADIUS, OpenVPN, strongSwan, OpenSSL, Python и установленными бинарниками GFW. Нужны `/state` и `/run` в tmpfs. Для IKEv2 включите XFRM, ESP и TUN в гостевом ядре.

```sh
GFW_QUALIFICATION_LAB=1 GFW_IKE_LAB=1 python3 scripts/qualification/auth.py
```

Для `load.py` подготовьте ALT Linux с пакетом GFW, tcpdump, Suricata с NFQUEUE, Python, пустым каталогом `/state` и ClickHouse на loopback TCP 8123. Для теста журналирования нужен доступ пользователя ClickHouse по умолчанию к созданию базы и тестового пользователя. Гостевое ядро должно поддерживать veth, nftables, conntrack, NFLOG, NFQUEUE, eBPF и XDP.

```sh
GFW_QUALIFICATION_LAB=1 python3 scripts/qualification/load.py standard
GFW_QUALIFICATION_LAB=1 python3 scripts/qualification/load.py extended
GFW_QUALIFICATION_LAB=1 python3 scripts/qualification/load.py patched
GFW_QUALIFICATION_LAB=1 python3 scripts/qualification/load.py soak
GFW_QUALIFICATION_LAB=1 python3 scripts/qualification/load.py long
GFW_QUALIFICATION_LAB=1 python3 scripts/qualification/load.py nfqueue
GFW_QUALIFICATION_LAB=1 python3 scripts/qualification/load.py nfqueue-long
```

`standard` проверяет всплески conntrack и NFLOG, повторную доставку после недоступности адреса ClickHouse, захват и IPS при 1, 10 и 40 тыс. пакетов/с. `extended` проверяет хвост PCAP, прогон при 100 тыс. пакетов/с, совместную работу модулей и переполнение NFQUEUE. `patched` повторяет AF_PACKET при 40 и 100 тыс. пакетов/с. Для A/B на 0.22.0 режим `immediate` добавляет флаг tcpdump только на время эксперимента. Каждая строка `RESULT` содержит JSON с измерениями.

Для `soak` и `long` используется GFW 0.22.1. В режиме `soak` шесть прогонов по 400 000 пакетов сравнивают штатный tcpdump и экспериментальный запуск без `-U`. Скрипт сверяет номера пакетов из полного PCAP со счётчиком потерь AF_PACKET и сохраняет число системных вызовов записи tcpdump из `/proc`. Затем 90 секунд одновременно работают IPS fail-closed, журналирование и захват с экспериментальной буферизацией.

Режим `long` подаёт 32 млн UDP-пакетов за 320 секунд со штатным tcpdump. Пять процентов пакетов несут строку, которая совпадает с тестовой сигнатурой Suricata. Скрипт сохраняет счётчики NFQUEUE, коллектора GFW, ClickHouse, интерфейсов veth и UDP-получателя. Захват идёт 12 отдельными сеансами по 25 секунд с `snaplen=64`. Это позволяет проверить совместную нагрузку в пределах лимита 256 МиБ на файл. Между сеансами есть паузы, а файлы удаляются после считывания метрик. Пакетное журналирование NFLOG использует штатное ограничение частоты.

`nfqueue` сравнивает одну и четыре очереди, глубину 4 096 и 16 384 пакета на очередь, а также сценарий с паузой Suricata в 100 мс. В каждом прогоне подаётся 1,2 млн пакетов при 100 тыс. пакетов/с, работают ClickHouse и AF_PACKET. Для сравнения временные обёртки Suricata и nftables действуют только внутри ВМ. С `GFW_QUALIFICATION_NFQ_NATIVE=1` скрипт проверяет агент с увеличенной очередью напрямую, включая переполнение, остановку слушателя и доступ из LAN.

Для `nfqueue-long` запустите одну версию GFW на чистой ВМ, затем другую на такой же ВМ. Режим использует штатные nftables и Suricata из пакета. Каждый прогон длится 320 секунд при 100 тыс. пакетов/с с IPS fail-closed, ClickHouse и 12 окнами AF_PACKET по 25 секунд. Счётчики nftables после IPS независимо проверяют прохождение пакетов с тестовой сигнатурой. Из пространства имён LAN скрипт каждую секунду делает авторизованный запрос к панели на HTTPS-порту 8443 с временным самоподписанным сертификатом. Для прогона нужен OpenSSL.

Дополнительный вариант `GFW_QUALIFICATION_NFQ_PAUSES=1` использует 180 секунд нагрузки, семь окон захвата и 11 пауз Suricata по 100 мс через каждые 15 секунд. Применяйте одинаковый вариант к обеим версиям. Сравнивайте его результаты отдельно от прогонов без пауз.
