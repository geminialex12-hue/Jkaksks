HamsSearch — Telegram OSINT bot (Python)

Это Telegram-бот, не сайт. GitHub используется для хранения исходного кода.
Для постоянной работы нужен worker-хостинг/сервер.

Файлы:
- bot.py: Telegram-бот, inline-меню и обработчики
- assets/banner.png: баннер, отправляемый в /start
- requirements.txt: зависимости
- Procfile: команда запуска worker на совместимом хостинге
- .env.example: пример переменных окружения

Запуск локально:
  pip install -r requirements.txt
  export BOT_TOKEN="токен_от_BotFather"
  export ADMIN_IDS="твой_telegram_user_id"
  python bot.py

На Windows PowerShell:
  py -m pip install -r requirements.txt
  $env:BOT_TOKEN="токен_от_BotFather"
  $env:ADMIN_IDS="твой_telegram_user_id"
  py bot.py

Для хостинга добавь переменные окружения BOT_TOKEN и ADMIN_IDS в настройках сервиса.
Команда запуска: python bot.py

Команды Telegram:
/start — меню
/admin — статистика и команды администратора
/broadcast текст — рассылка от администратора

Функции:
- Domain: публичные DNS-записи и базовая RDAP-информация
- Email: синтаксис адреса и MX-записи домена
- Phone: проверка международного формата и регионального кода
- IP/DNS: A-записи домена
- Google Dorks: генератор ограниченных запросов по публичным страницам и документам

Безопасность:
- Не публикуй токен бота в GitHub.
- BOT_TOKEN и ADMIN_IDS задавай в Secrets/Environment Variables хостинга.
- Бот не ищет частных лиц, владельцев номеров, пароли или закрытые аккаунты.
- Результаты DNS/RDAP зависят от доступности внешних сервисов.
