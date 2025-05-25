# telegram_notifier — Модуль ядра Linux для отправки сообщений в Telegram

Этот модуль ядра позволяет отправлять сообщения в Telegram напрямую из ядра Linux, используя встроенный вызов `curl` через `call_usermodehelper()`.

---

## 📦 Требования

- Linux (поддержка сборки модулей)
- Установленный `curl`
- Компилятор ядра (`build-essential`, `linux-headers-$(uname -r)`)
- Telegram-бот и ваш `chat_id` (можно получить у [@userinfobot](https://t.me/userinfobot))

---

## ⚙️ Сборка модуля

1. Склонируйте или создайте каталог с файлом `telegram_notifier.c` и `Makefile`

2. Соберите модуль:

```bash
make
sudo insmod telegram_notifier.ko
sudo mknod /dev/telegram_notifier c 241 0
sudo chmod 666 /dev/telegram_notifier
```

3. Как пользоваться:
```bash
echo "TOKEN=ВАШ_ТОКЕН" | sudo tee /dev/telegram_notifier #Сначало задаём токен для нашего бота который будет писать сообщение
echo "CHAT_ID=ВАШ_CHAT_ID" | sudo tee /dev/telegram_notifier # Задаём chad_id, который указывает в какой чат или кому мы хотим написать сообщение

echo "MSG=Hello World!" | sudo tee /dev/telegram_notifier # С кириллицей пока что были проблемы
```
