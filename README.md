```markdown
# MikroTik SSH Brute-Force Protection Script

Решается проблема невозможности прямого отслеживания ответа роутера Mikrotik из-за шифрования протокола.

Автоматический скрипт для защиты MikroTik роутеров от брутфорс-атак на SSH и другие сервисы. Анализирует логи на наличие неудачных попыток входа и автоматически добавляет IP-адреса злоумышленников в черный список с временной блокировкой.

## Возможности

- **Мониторинг логов** — отслеживает записи `login failure` в системных логах
- **Автоматическая блокировка** — добавляет IP в address-list с таймаутом (по умолчанию 3 дня)
- **Защита от дублей** — проверяет наличие IP в списке перед добавлением
- **Ограничение нагрузки** — обрабатывает только последние 100 записей лога
- **Обработка ошибок** — корректно обрабатывает некорректные IP-адреса

## Требования

- RouterOS v6.x или v7.x
- Права доступа: read, write, test, policy
- Включенное логирование системных событий (`/system logging` → topics: system)

## Установка

### 1. Создание address-list (черный список)

```routeros
/ip firewall address-list add list=Blacklist comment="Auto-generated blocked IPs"
```

2. Создание правила файрвола

Добавьте правило для блокировки трафика из черного списка:

```routeros
/ip firewall filter add chain=input src-address-list=Blacklist action=drop comment="Drop Blacklist IPs"
```

Или для более точной настройки — блокируйте только новые соединения:

```routeros
/ip firewall filter add chain=input connection-state=new src-address-list=Blacklist action=drop place-before=0 comment="Block brute-force IPs"
```

3. Добавление скрипта

```routeros
/system script add name=BruteForceProtect source={
    :local targetList "Blacklist";
    
    :local logList [/log find where topics~"system" && message~"login failure"];
    :local logCount [:len $logList];
    
    :if ($logCount > 100) do={
        :set logList [:pick $logList ($logCount - 100) $logCount];
    }
    
    :foreach i in=$logList do={
        :local msg [/log get $i message];
        :local fromPos [:find $msg "from "];
        
        :if ([:typeof $fromPos] != "nil") do={
            :local ipStr [:pick $msg ($fromPos + 5) [:len $msg]];
            :local spacePos [:find $ipStr " "];
            
            :if ([:typeof $spacePos] != "nil") do={
                :set ipStr [:pick $ipStr 0 $spacePos];
            }
            
            :if ([:find $ipStr "."] >= 0) do={
                :do {
                    :local ipAddr [:toip $ipStr];
                    
                    :if ([/ip firewall address-list find where list=$targetList address=$ipAddr] = "") do={
                        /ip firewall address-list add address=$ipAddr list=$targetList timeout=3d comment="Banned via Log";
                        :log warning ("BANNED IP FROM LOG: " . $ipAddr);
                    }
                } on-error={}
            }
        }
    }
}
```

4. Настройка расписания (Scheduler)

Создайте задачу для периодического запуска скрипта (каждые 5 минут):

```routeros
/system scheduler add name=RunBruteProtect interval=5m on-event="/system script run BruteForceProtect" policy=read,write,test,policy
```

Проверка работы

Просмотр заблокированных IP

```routeros
/ip firewall address-list print where list=Blacklist
```

Просмотр логов скрипта

```routeros
/log print where message~"BANNED IP"
```

Ручной запуск скрипта

```routeros
/system script run BruteForceProtect
```

Настройка

Изменение имени списка

Замените переменную `:local targetList "Blacklist"` на нужное имя address-list.

Изменение времени блокировки

В строке добавления в список измените `timeout=3d`:
- `1h` — 1 час
- `30m` — 30 минут
- `1w` — 1 неделя

Изменение лимита обрабатываемых записей

В строке `:if ($logCount > 100)` замените `100` на нужное количество.

Как это работает

1. Получение логов — скрипт запрашивает последние записи с темой `system` и сообщением `login failure`
2. Парсинг IP — извлекает IP-адрес из строки `failed to login from 192.168.1.100`
3. Валидация — проверяет корректность IP-адреса
4. Проверка дублей — убеждается, что IP еще не в черном списке
5. Блокировка — добавляет IP в address-list с таймаутом
6. Логирование — создает запись в логе о блокировке

Устранение неполадок

Скрипт не добавляет IP в список

Проверьте формат логов:

```routeros
/log print where topics~"system" && message~"login failure"
```

Убедитесь, что сообщения содержат `from ` перед IP-адресом.

Скрипт падает с ошибкой

Проверьте права доступа у scheduler:

```routeros
/system scheduler print
```

Политика должна включать: `read,write,test,policy`

Слишком много записей обрабатывается

Уменьшите лимит с 100 до 20-30 для снижения нагрузки на CPU.

Безопасность

- Скрипт не блокирует IP навсегда — используется таймаут 3 дня
- Рекомендуется добавить в белый список (address-list с исключением) свои постоянные IP-адреса
- Для критичных систем используйте вместе с [Port Knocking](https://wiki.mikrotik.com/wiki/Port_Knocking) или VPN


```
