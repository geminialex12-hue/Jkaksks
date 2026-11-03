import os
import re
import json
import sqlite3
import asyncio
from urllib.parse import quote
from datetime import datetime, timezone

import aiohttp
import dns.resolver
import phonenumbers
from email_validator import validate_email, EmailNotValidError
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, ContextTypes, filters
)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()}
DB_PATH = os.getenv("DB_PATH", "hamssearch.sqlite3")

if not BOT_TOKEN:
    raise RuntimeError("Set BOT_TOKEN in environment variables.")

db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.execute("""CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    first_seen TEXT
)""")
db.commit()

MENU = InlineKeyboardMarkup([
    [InlineKeyboardButton("🌐 Domain OSINT", callback_data="domain"),
     InlineKeyboardButton("📧 Email check", callback_data="email")],
    [InlineKeyboardButton("☎️ Phone format", callback_data="phone"),
     InlineKeyboardButton("🛰 IP / DNS", callback_data="ip")],
    [InlineKeyboardButton("🔎 Google Dorks", callback_data="dorks"),
     InlineKeyboardButton("ℹ️ Help", callback_data="help")],
])

BACK = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Главное меню", callback_data="home")]])

def remember_user(user):
    db.execute(
        "INSERT OR IGNORE INTO users(user_id, username, first_seen) VALUES(?,?,?)",
        (user.id, user.username or "", datetime.now(timezone.utc).isoformat())
    )
    db.commit()

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

def clean_domain(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0].split(":")[0].rstrip(".")
    if len(value) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        raise ValueError("Укажи корректный домен, например example.com")
    return value

async def fetch_json(session, url):
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=12), headers={"User-Agent": "HamsSearch/1.0"}) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        return await resp.json(content_type=None)

async def domain_report(domain: str) -> str:
    lines = [f"🌐 <b>DOMAIN REPORT</b>", f"<code>{domain}</code>"]
    for record in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, domain, record, lifetime=4)
            vals = [str(x).replace('"', '') for x in answers]
            lines.append(f"\n<b>{record}</b>\n" + "\n".join(f"• <code>{v[:180]}</code>" for v in vals[:6]))
        except Exception:
            lines.append(f"\n<b>{record}</b>\n• Нет доступных записей")
    try:
        async with aiohttp.ClientSession() as session:
            data = await fetch_json(session, f"https://rdap.org/domain/{quote(domain)}")
        status = ", ".join(data.get("status", [])[:4]) or "не указан"
        lines.append(f"\n<b>RDAP status</b>\n• {status}")
        events = data.get("events", [])
        for ev in events:
            if ev.get("eventAction") in ("registration", "expiration", "last changed"):
                lines.append(f"• {ev.get('eventAction')}: {ev.get('eventDate', '')[:10]}")
    except Exception:
        lines.append("\n<b>RDAP</b>\n• Данные регистратора сейчас недоступны")
    lines.append("\n<i>Только технические публичные сведения о домене; персональные данные регистрантов не извлекаются.</i>")
    return "\n".join(lines)

async def email_report(value: str) -> str:
    try:
        checked = validate_email(value.strip(), check_deliverability=False)
        address = checked.normalized
        domain = checked.domain
    except EmailNotValidError as e:
        return f"❌ Некорректный адрес: <code>{str(e)[:180]}</code>"
    try:
        records = await asyncio.to_thread(dns.resolver.resolve, domain, "MX", lifetime=4)
        mx = "\n".join(f"• <code>{str(x.exchange).rstrip('.')}</code>" for x in list(records)[:5])
        mx_status = "MX-записи найдены"
    except Exception:
        mx, mx_status = "• MX-записи не найдены или DNS недоступен", "MX не подтверждён"
    return (
        "📧 <b>EMAIL CHECK</b>\n"
        f"Адрес: <code>{address}</code>\n"
        f"Домен: <code>{domain}</code>\n"
        f"Статус: {mx_status}\n{mx}\n\n"
        "<i>Проверка не устанавливает владельца, существование ящика или утечки данных.</i>"
    )

def phone_report(value: str) -> str:
    try:
        number = phonenumbers.parse(value.strip(), None)
        if not phonenumbers.is_possible_number(number):
            return "❌ Номер не похож на корректный международный номер."
        valid = phonenumbers.is_valid_number(number)
        region = phonenumbers.region_code_for_number(number) or "не определён"
        return (
            "☎️ <b>PHONE FORMAT CHECK</b>\n"
            f"Формат E.164: <code>{phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)}</code>\n"
            f"Региональный код: <code>{region}</code>\n"
            f"Формат: {'проверен' if valid else 'возможен, но не подтверждён'}\n\n"
            "<i>Поиск владельца, адреса или аккаунтов по номеру не выполняется.</i>"
        )
    except Exception:
        return "❌ Введи номер в международном формате, например <code>+358401234567</code>."

async def domain_ip_report(domain: str) -> str:
    domain = clean_domain(domain)
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, "A", lifetime=4)
        ips = list(dict.fromkeys(str(x) for x in answers))[:5]
    except Exception:
        return "Не удалось получить A-записи домена."
    out = [f"🛰 <b>DNS / IP</b>\nДомен: <code>{domain}</code>"]
    for ip in ips:
        out.append(f"• <code>{ip}</code>")
    out.append("\n<i>Показаны IP-адреса инфраструктуры домена, а не местоположение человека.</i>")
    return "\n".join(out)

def dork_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("Страницы сайта", callback_data="dork_pages"),
         InlineKeyboardButton("PDF-документы", callback_data="dork_pdf")],
        [InlineKeyboardButton("Публичные справочные материалы", callback_data="dork_docs"),
         InlineKeyboardButton("⬅️ Назад", callback_data="home")]
    ])

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    remember_user(update.effective_user)
    context.user_data.pop("mode", None)
    caption = (
        "🛰 <b>HamsSearch</b>\n"
        "<i>Public OSINT • Domain Intelligence • Search</i>\n\n"
        "Выбери инструмент. Бот работает с публичными техническими данными и не ищет частных лиц."
    )
    banner_path = os.path.join(os.path.dirname(__file__), "assets", "banner.png")
    if os.path.exists(banner_path):
        with open(banner_path, "rb") as banner:
            await update.message.reply_photo(banner, caption=caption, reply_markup=MENU, parse_mode="HTML")
    else:
        await update.message.reply_text(caption, reply_markup=MENU, parse_mode="HTML")

async def admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Доступ запрещён.")
        return
    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    await update.message.reply_text(
        f"🛡 <b>HamsSearch Admin</b>\nПользователей: <b>{count}</b>\n"
        "Команды:\n<code>/broadcast текст</code> — объявление всем пользователям",
        parse_mode="HTML"
    )

async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    message = " ".join(context.args).strip()
    if not message:
        await update.message.reply_text("Использование: /broadcast текст")
        return
    ids = [r[0] for r in db.execute("SELECT user_id FROM users").fetchall()]
    sent = 0
    for uid in ids:
        try:
            await context.bot.send_message(uid, message)
            sent += 1
            await asyncio.sleep(0.04)
        except Exception:
            pass
    await update.message.reply_text(f"Готово. Доставлено: {sent}/{len(ids)}")

async def on_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    key = q.data
    if key == "home":
        context.user_data.pop("mode", None)
        await q.edit_message_text("🛰 <b>HamsSearch</b>\nВыбери инструмент:", reply_markup=MENU, parse_mode="HTML")
    elif key in ("domain", "email", "phone", "ip"):
        context.user_data["mode"] = key
        prompts = {
            "domain": "🌐 Отправь домен, например <code>example.com</code>.",
            "email": "📧 Отправь адрес для проверки синтаксиса и MX домена.",
            "phone": "☎️ Отправь номер в международном формате, например <code>+358401234567</code>.",
            "ip": "🛰 Отправь домен, чтобы посмотреть его публичные DNS A-записи."
        }
        await q.edit_message_text(prompts[key], reply_markup=BACK, parse_mode="HTML")
    elif key == "dorks":
        await q.edit_message_text(
            "🔎 <b>GOOGLE DORK BUILDER</b>\nВыбери безопасный тип поиска по публичному сайту:",
            reply_markup=dork_menu(), parse_mode="HTML"
        )
    elif key.startswith("dork_"):
        context.user_data["mode"] = key
        await q.edit_message_text("Введи домен сайта, который принадлежит тебе или который ты уполномочен исследовать. Например <code>example.com</code>.", reply_markup=BACK, parse_mode="HTML")
    elif key == "help":
        await q.edit_message_text(
            "ℹ️ <b>Возможности</b>\n"
            "• Domain: DNS + базовый RDAP\n• Email: синтаксис + MX домена\n"
            "• Phone: формат и региональный код\n• IP/DNS: адреса, опубликованные доменом\n"
            "• Google Dorks: поиск публичных страниц и документов\n\n"
            "Бот не выполняет reverse lookup людей, поиск утечек, паролей или закрытых панелей.",
            reply_markup=BACK, parse_mode="HTML"
        )

async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    remember_user(update.effective_user)
    mode = context.user_data.get("mode")
    if not mode:
        await update.message.reply_text("Выбери действие в меню /start.")
        return
    value = update.message.text.strip()
    context.user_data.pop("mode", None)
    try:
        if mode == "domain":
            result = await domain_report(clean_domain(value))
        elif mode == "email":
            result = await email_report(value)
        elif mode == "phone":
            result = phone_report(value)
        elif mode == "ip":
            result = await domain_ip_report(value)
        elif mode.startswith("dork_"):
            domain = clean_domain(value)
            if mode == "dork_pages":
                query = f"site:{domain}"
            elif mode == "dork_pdf":
                query = f"site:{domain} filetype:pdf"
            else:
                query = f"site:{domain} documentation OR guide OR help"
            url = "https://www.google.com/search?q=" + quote(query)
            result = f"🔎 <b>GOOGLE SEARCH</b>\nЗапрос: <code>{query}</code>\n\n<a href=\"{url}\">Открыть результаты Google</a>"
        else:
            result = "Неизвестный режим. Нажми /start."
    except ValueError as e:
        result = f"❌ {str(e)}"
    except Exception:
        result = "⚠️ Не удалось выполнить проверку. Попробуй позже."
    await update.message.reply_text(result, parse_mode="HTML", reply_markup=BACK, disable_web_page_preview=True)

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("admin", admin))
    app.add_handler(CommandHandler("broadcast", broadcast))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    print("HamsSearch is running...")
    app.run_polling()

if __name__ == "__main__":
    main()
