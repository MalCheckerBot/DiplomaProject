import telebot
import requests
from bs4 import BeautifulSoup
import base64
import time
import logging
import re
import threading
import os
import hashlib
from telebot.types import ReplyKeyboardMarkup, KeyboardButton
from cryptography.fernet import Fernet
from config_ob import (ENCRYPTED_TELEGRAM_BOT_TOKEN, ENCRYPTED_VIRUSTOTAL_API_KEY,
                       ENCRYPTED_GOOGLE_SAFE_BROWSING_API_KEY, ENCRYPTED_AIML_API_KEY,
                       ENCRYPTED_AIML_API_URL, ENCRYPTION_KEY)
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from dotenv import load_dotenv
import datetime
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
cipher = Fernet(ENCRYPTION_KEY)
TELEGRAM_BOT_TOKEN = cipher.decrypt(ENCRYPTED_TELEGRAM_BOT_TOKEN).decode()
VIRUSTOTAL_API_KEY = cipher.decrypt(ENCRYPTED_VIRUSTOTAL_API_KEY).decode()
GOOGLE_SAFE_BROWSING_API_KEY = cipher.decrypt(ENCRYPTED_GOOGLE_SAFE_BROWSING_API_KEY).decode()
AIML_API_KEY = cipher.decrypt(ENCRYPTED_AIML_API_KEY).decode()
AIML_API_URL = cipher.decrypt(ENCRYPTED_AIML_API_URL).decode()
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)
load_dotenv()
GOOGLE_CREDENTIALS_FILE = os.getenv('GOOGLE_CREDENTIALS_FILE')
SPREADSHEET_ID = os.getenv('SPREADSHEET_ID')
CLICKS_SHEET_NAME = os.getenv('CLICKS_SHEET_NAME', 'Клики')
USERS_SHEET_NAME = os.getenv('USERS_SHEET_NAME', 'Пользователи')
if not os.path.exists(GOOGLE_CREDENTIALS_FILE):
    logger.error(f"Файл {GOOGLE_CREDENTIALS_FILE} не найден!")
    exit(1)
scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
try:
    credentials = ServiceAccountCredentials.from_json_keyfile_name(GOOGLE_CREDENTIALS_FILE, scope)
    client = gspread.authorize(credentials)
    spreadsheet = client.open_by_key(SPREADSHEET_ID)
    try:
        clicks_sheet = spreadsheet.worksheet(CLICKS_SHEET_NAME)
        headers = clicks_sheet.row_values(1)
        if not headers or len(headers) < 3:
            clicks_sheet.clear()
            clicks_sheet.append_row(['ID пользователя', 'Время', 'Действие'])
    except gspread.exceptions.WorksheetNotFound:
        clicks_sheet = spreadsheet.add_worksheet(title=CLICKS_SHEET_NAME, rows=1000, cols=3)
        clicks_sheet.append_row(['ID пользователя', 'Время', 'Действие'])
    try:
        users_sheet = spreadsheet.worksheet(USERS_SHEET_NAME)
        headers = users_sheet.row_values(1)
        if not headers or len(headers) < 3:
            users_sheet.clear()
            users_sheet.append_row(['ID пользователя', 'Имя пользователя', 'Время регистрации'])
    except gspread.exceptions.WorksheetNotFound:
        users_sheet = spreadsheet.add_worksheet(title=USERS_SHEET_NAME, rows=1000, cols=3)
        users_sheet.append_row(['ID пользователя', 'Имя пользователя', 'Время регистрации'])
except Exception as e:
    logger.error(f"Ошибка при настройке Google Sheets: {e}")
    exit(1)
def save_user(user_id, username):
    try:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cell = users_sheet.findall(str(user_id))
        if not cell:
            users_sheet.append_row([str(user_id), username or 'Нет имени', now])
    except Exception as e:
        logger.error(f"Ошибка сохранения пользователя: {e}")
def save_action(user_id, action_text):
    try:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clicks_sheet.append_row([str(user_id), now, action_text])
    except Exception as e:
        logger.error(f"Ошибка сохранения действия: {e}")
user_state = {}
user_data = {}
results = {}
stop_flags = {}
def is_valid_link(text):
    domain_pattern = r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$'
    return bool(re.match(domain_pattern, text))
def get_main_keyboard():
    markup = ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(KeyboardButton("🔗 Проверить ссылку"), KeyboardButton("☎️ Узнать про номер"))
    markup.add(KeyboardButton("🗂 Проверить файл"), KeyboardButton("🤓 Задать вопрос ИИ"))
    markup.add(KeyboardButton("👀 Почитать о нас"))
    return markup
def get_cancel_keyboard():
    markup = ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(KeyboardButton("Отменить⛔️"))
    return markup
def get_confirm_keyboard():
    markup = ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
    markup.add(KeyboardButton("Да✅"), KeyboardButton("Нет⛔️"))
    return markup
def animate_link_loading(bot, chat_id, message_id):
    animation_frames = ["Проверяю... 🔍", "Проверяю... 🔍✨", "Проверяю... 🔍✨🔮"]
    frame_index = 0
    stop_flags[chat_id] = False
    while not stop_flags[chat_id]:
        try:
            bot.edit_message_text(animation_frames[frame_index], chat_id=chat_id, message_id=message_id)
            frame_index = (frame_index + 1) % len(animation_frames)
            time.sleep(1.5)
            if chat_id in results and results[chat_id] is not None:
                stop_flags[chat_id] = True
        except telebot.apihelper.ApiTelegramException:
            break
def animate_ai_loading(bot, chat_id, message_id):
    animation_frames = ["Думаю... 🤓", "Думаю... 🤓💡", "Думаю... 🤓💡⚡"]
    frame_index = 0
    stop_flags[chat_id] = False
    while not stop_flags[chat_id]:
        try:
            bot.edit_message_text(animation_frames[frame_index], chat_id, message_id)
            frame_index = (frame_index + 1) % len(animation_frames)
            time.sleep(1.5)
            if chat_id in results and results[chat_id] is not None:
                stop_flags[chat_id] = True
        except telebot.apihelper.ApiTelegramException:
            break
def animate_file_loading(bot, chat_id, message_id):
    animation_frames = ["Проверяю... 🔍", "Проверяю... 🔍✨", "Проверяю... 🔍✨🔮"]
    frame_index = 0
    stop_flags[chat_id] = False
    while not stop_flags[chat_id]:
        try:
            bot.edit_message_text(animation_frames[frame_index], chat_id, message_id)
            frame_index = (frame_index + 1) % len(animation_frames)
            time.sleep(3)
            if chat_id in results and results[chat_id] is not None:
                stop_flags[chat_id] = True
        except telebot.apihelper.ApiTelegramException:
            break
def check_link(url):
    vt_result = check_with_virustotal(url)
    vt_message = "🦠 VirusTotal:\n" + (vt_result[
                                          "error"] if "error" in vt_result else f"Угрозы: {vt_result['malicious']}/{vt_result['total_engines']} ⚠️\nОтчёт: {vt_result['report_url']}")
    sa_result = check_with_scamadviser(url)
    sa_message = "☄️ ScamAdviser:\n" + (sa_result[
                                            "error"] if "error" in sa_result else f"Уровень доверия: {sa_result['trust_score']} / 100 ⭐\nОтчёт: {sa_result['report_url']}")
    gsb_result = check_with_google_safe_browsing(url)
    gsb_message = "☁️ Google Safe Browsing:\n" + (
        gsb_result["error"] if "error" in gsb_result else "Ссылка безопасна ✅" if gsb_result[
            "is_safe"] else f"Найдены угрозы: {', '.join(gsb_result['threats'])} ⚠️")
    result = f"{vt_message}\n\n{sa_message}\n\n{gsb_message}"
    is_dangerous = False
    is_safe = True
    if "error" not in vt_result:
        if vt_result["malicious"] > 0:
            is_dangerous = True
            is_safe = False
    else:
        is_safe = False
    if "error" not in sa_result:
        if int(sa_result["trust_score"]) < 75:
            is_dangerous = True
            is_safe = False
    else:
        is_safe = False
    if "error" not in gsb_result:
        if not gsb_result["is_safe"]:
            is_dangerous = True
            is_safe = False
    else:
        is_safe = False
    if is_dangerous:
        result += "\n\n📝 Итог:\nДанная ссылка - Потенциально Вредоносная.\nНе рекомендую её открывать❗️"
    elif is_safe:
        result += "\n\n📝 Итог:\nДанная ссылка - Безопасна ✅"
    return result
def check_phone(phone_number):
    cleaned_number = re.sub(r'[()\-\s]+', '', phone_number.strip())
    if cleaned_number.startswith('8') and len(cleaned_number) >= 10:
        cleaned_number = '+7' + cleaned_number[1:]
    if not cleaned_number.startswith('+'):
        return {"error": "☎️ Номер должен начинаться с плюса (+)\nПопробуйте ещё раз 🥺"}
    if not cleaned_number[1:].isdigit():
        return {"error": "☎️ Номер должен содержать только цифры после плюса\nПопробуйте ещё раз 🥺"}
    spam_result = check_with_spamcalls(cleaned_number)
    if "error" in spam_result:
        return spam_result["error"]
    else:
        if spam_result["is_spam"]:
            return f"⚠️ Номер {cleaned_number} отмечен как спам или мошенничество.\n\n🔎 Детали:\n{spam_result['details']}\n📝 Отчёт: {spam_result['report_url']}"
        else:
            return f"✅ Номер {cleaned_number} безопасен.\n\n📝 Отчёт: {spam_result['report_url']}"
def check_with_virustotal(url):
    vt_url = 'https://www.virustotal.com/api/v3/urls'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    data = {'url': url}
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    scan_response = requests.post(vt_url, headers=headers, data=data)
    if scan_response.status_code == 200:
        analysis_id = scan_response.json().get('data', {}).get('id', None)
        report_url = f'https://www.virustotal.com/gui/url/{encoded_url}/detection'
        if analysis_id:
            while True:
                analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                                 headers=headers)
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json().get('data', {}).get('attributes', {})
                    status = analysis_data.get('status')
                    if status == 'completed':
                        stats = analysis_data.get('stats', {})
                        malicious_count = stats.get('malicious', 0)
                        total_engines = stats.get('harmless', 0) + stats.get('malicious', 0) + stats.get('suspicious',
                                                                                                         0) + stats.get(
                            'undetected', 0)
                        return {"malicious": malicious_count, "total_engines": total_engines, "report_url": report_url}
                    elif status == 'queued':
                        time.sleep(10)
                    else:
                        return {"error": f"Ошибка, статус анализа.\nПопробуйте ещё раз 🥺"}
                else:
                    return {"error": "Ошибка при получении результатов анализа.\nПопробуйте ещё раз 🥺"}
        else:
            return {"error": "Ошибка, не удалось получить ID анализа.\nПопробуйте ещё раз 🥺"}
    else:
        return {"error": f"Ошибка запроса VirusTotal.\nПопробуйте ещё раз 🥺"}
def check_with_scamadviser(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        report_url = f"https://www.scamadviser.com/check-website/{domain}"
        response = requests.get(report_url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "lxml")
            trustscore_container = soup.find(
                class_='tile__body tile__body--no-padding d-flex flex-column justify-content-center')
            if trustscore_container:
                trust_score_element = trustscore_container.find("div", id="trustscore")
                if trust_score_element and "data-rating" in trust_score_element.attrs:
                    trust_score = trust_score_element["data-rating"].strip()
                    return {"trust_score": trust_score, "report_url": report_url}
            return {"error": "Ошибка, уровень доверия не найден.\nПопробуйте ещё раз 🥺"}
        else:
            return {"error": "Ошибка запроса к ScamAdviser.\nПопробуйте ещё раз 🥺"}
    except Exception as e:
        return {"error": "Ошибка парсинга ScamAdviser.\nПопробуйте ещё раз 🥺"}
def check_with_google_safe_browsing(url):
    api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}'
    payload = {
        "client": {"clientId": "your-client-id", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=payload)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data:
                threats = [match['threatType'] for match in data['matches']]
                return {"threats": threats, "is_safe": False}
            else:
                return {"threats": [], "is_safe": True}
        else:
            return {"error": "Ошибка запроса Google Safe Browsing.\nПопробуйте ещё раз 🥺"}
    except Exception as e:
        return {"error": "Ошибка при проверке через Google Safe Browsing.\nПопробуйте ещё раз 🥺"}
def check_with_spamcalls(phone_number):
    try:
        if not phone_number.startswith('+'):
            return {"error": "☎️ Номер должен начинаться с плюса (+)\nПопробуйте ещё раз 🥺"}
        if not phone_number[1:].isdigit():
            return {"error": "☎️ Номер должен содержать только цифры после плюса\nПопробуйте ещё раз 🥺"}
        url = f'https://spamcalls.net/en/search?q={phone_number}'
        proxies = {
            "http": "http://kvufzuvo:k703tsxis9nt@198.23.239.134:6540",
            "https": "http://kvufzuvo:k703tsxis9nt@198.23.239.134:6540"
        }
        response = requests.get(url, proxies=proxies, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "lxml")
            title = soup.find("h1")
            if title and phone_number in title.text:
                blocks = soup.find_all("div", class_="col-lg-12 clickable-scroll-to")
                details = {}
                for block in blocks:
                    h3 = block.find("h3")
                    if h3:
                        key = h3.text.strip()
                        if "Most frequently reported" in key:
                            key = "Most frequently reported"
                        value = h3.find_next("h4").text.strip() if h3.find_next("h4") else "Информация отсутствует."
                        details[key] = value
                details_message = ""
                if "Spam-Risk" in details:
                    details_message += f"Уровень Спама: {details['Spam-Risk']}\n"
                if "Country of origin" in details:
                    details_message += f"Страна происхождения: {details['Country of origin']}\n"
                if "Most frequently reported" in details:
                    details_message += f"Чаще всего жалуются на: {details['Most frequently reported']}\n"
                report_url = url
                if "Spam-Risk" in details or "Most frequently reported" in details:
                    return {"is_spam": True, "details": details_message, "report_url": report_url}
                else:
                    return {"is_spam": False, "details": "⚠️ Номер не найден в базе данных спама.",
                            "report_url": report_url}
            else:
                return {"is_spam": False, "details": "⚠️ Номер не найден в базе данных спама.", "report_url": url}
        else:
            return {"error": f"⚠️ Ошибка запроса к SpamCalls.\nПопробуйте ещё раз 🥺"}
    except Exception as e:
        return {"error": f"⚠️ Ошибка при проверке через SpamCalls.\nПопробуйте ещё раз 🥺"}
def check_file_with_virustotal(file_path):
    vt_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        with open(file_path, "rb") as file:
            file_content = file.read()
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            file.seek(0)
            files = {"file": (file_path.split("/")[-1], file)}
            scan_response = requests.post(vt_url, headers=headers, files=files)
        if scan_response.status_code == 200:
            analysis_id = scan_response.json().get("data", {}).get("id")
            report_url = f"https://www.virustotal.com/gui/file/{sha256_hash}/detection"
            while True:
                analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                                 headers=headers)
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json().get("data", {}).get("attributes", {})
                    status = analysis_data.get("status")
                    if status == "completed":
                        stats = analysis_data.get("stats", {})
                        malicious_count = stats.get("malicious", 0)
                        total_engines = stats.get("harmless", 0) + stats.get("malicious", 0) + stats.get("suspicious",
                                                                                                         0) + stats.get(
                            "undetected", 0)
                        result = f"🦠 VirusTotal:\nУгрозы: {malicious_count}/{total_engines} ⚠️\nОтчёт: {report_url}"
                        if malicious_count > 0:
                            result += "\n\n📝 Итог:\nЭтот файл - Потенциально Вредоносный.\nНе рекомендую его открывать❗️"
                        else:
                            result += "\n\n📝 Итог:\nЭтот файл - Безопасен ✅"
                        return result
                    elif status == "queued":
                        time.sleep(10)
                    else:
                        return f"Ошибка, статус анализа.\nПопробуйте ещё раз 🥺"
                else:
                    return "Ошибка при получении результатов анализа.\nПопробуйте ещё раз 🥺"
        else:
            return f"Ошибка запроса VirusTotal.\nПопробуйте ещё раз 🥺"
    except Exception as e:
        return "Ошибка при загрузке файла.\nПопробуйте ещё раз 🥺"
def get_ai_response(query):
    headers = {
        "Authorization": f"Bearer {AIML_API_KEY}",
        "Content-Type": "application/json"
    }
    prompt = f"Давай краткие ответы в 2-3 предложения,максимум 200 символов.Если вопрос не по теме кибербезопасности,мошенничества и так далее,скажи:'Извини, я отвечаю только на вопросы про кибербезопасность и мошенничество.'Если вопрос неясен или неполный,отвечай:'Извини, я не понял твой вопрос. Задай его точнее, пожалуйста!',не пытайся продолжать или угадывать вопрос.Вот вопрос:{query}"
    payload = {
        "model": "gpt-3.5-turbo-instruct",
        "prompt": prompt,
        "max_tokens": 200,
        "temperature": 0.3
    }
    try:
        response = requests.post(AIML_API_URL, headers=headers, json=payload)
        if response.status_code in (200, 201):
            result = response.json()
            clean_text = result["choices"][0]["text"].strip().replace("\n\n", " ").replace("\n", " ")
            return f"🤓 Ответ:\n{clean_text}"
        else:
            return f"⚠️ Неизвестная ошибка.\nПопробуйте ещё раз 🥺"
    except Exception as e:
        return "⚠️ Что-то пошло не так с ИИ.\nПопробуйте ещё раз 🥺"
def reset_state(user_id):
    user_state[user_id] = 'start'
    if user_id in user_data:
        del user_data[user_id]
    if user_id in results:
        del results[user_id]
    if user_id in stop_flags:
        stop_flags[user_id] = True
        del stop_flags[user_id]
@bot.message_handler(commands=['start'])
def start_message(message):
    reset_state(message.chat.id)
    save_user(message.chat.id, message.from_user.username)
    save_action(message.chat.id, "/start")
    bot.send_message(message.chat.id,
                     "👋🏻 Привет! Я бот для проверки ссылок, номеров и файлов.\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                     reply_markup=get_main_keyboard())
@bot.message_handler(commands=['about'])
def about_message(message):
    reset_state(message.chat.id)
    save_action(message.chat.id, "/about")
    bot.send_message(message.chat.id,
                     "🎓 Я дипломный проект студентов Astana IT University\n"
                     "В частности Alikhan Zhuma, Valerii Pankov и Rodion Kuznetsov.\n"
                     "Меня создали, чтобы помочь проверять подозрительные ссылки, номера и файлы 👁")
    bot.send_message(message.chat.id,
                     "😊 Что хотите сделать дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                     reply_markup=get_main_keyboard())
@bot.message_handler(commands=['link'])
def check_message(message):
    user_state[message.chat.id] = 'awaiting_link'
    save_action(message.chat.id, "/link")
    bot.send_message(message.chat.id,
                     "🔗 Жду подозрительную ссылку.\nЖдать около 15 секунд ⌛️\n\n⛔️ /cancel - отменить действие",
                     reply_markup=get_cancel_keyboard())
@bot.message_handler(commands=['number'])
def check_phone_message(message):
    user_state[message.chat.id] = 'awaiting_phone'
    save_action(message.chat.id, "/number")
    bot.send_message(message.chat.id,
                     "☎️ Жду от тебя номер (например, +7 707 404 6633).\n\n⛔️ /cancel - отменить действие",
                     reply_markup=get_cancel_keyboard())
@bot.message_handler(commands=['chat'])
def chat_message(message):
    user_state[message.chat.id] = 'awaiting_chat'
    save_action(message.chat.id, "/chat")
    bot.send_message(message.chat.id,
                     "🤓 Задавай вопрос, я тебе отвечу.\n\n⛔️ /cancel - отменить действие",
                     reply_markup=get_cancel_keyboard())
@bot.message_handler(commands=['file'])
def check_file_message(message):
    user_state[message.chat.id] = 'awaiting_file'
    save_action(message.chat.id, "/file")
    bot.send_message(message.chat.id,
                     "🗂 Жду от тебя файл для проверки.\nЖдать 1-4 минуты ⌛️\n(максимум 20 МБ)\n\n⛔️ /cancel - отменить действие",
                     reply_markup=get_cancel_keyboard())
@bot.message_handler(
    func=lambda message: message.text in ["🔗 Проверить ссылку", "☎️ Узнать про номер", "🗂 Проверить файл",
                                          "🤓 Задать вопрос ИИ", "👀 Почитать о нас"])
def handle_button(message):
    user_id = message.chat.id
    if message.text == "🔗 Проверить ссылку":
        user_state[user_id] = 'awaiting_link'
        save_action(user_id, "Проверить ссылку")
        bot.send_message(user_id,
                         "🔗 Жду подозрительную ссылку.\nЖдать около 15 секунд ⌛️\n\n⛔️ /cancel - отменить действие",
                         reply_markup=get_cancel_keyboard())
    elif message.text == "☎️ Узнать про номер":
        user_state[user_id] = 'awaiting_phone'
        save_action(user_id, "Узнать про номер")
        bot.send_message(user_id,
                         "☎️ Жду от тебя номер (например, +7 707 404 6633).\n\n⛔️ /cancel - отменить действие",
                         reply_markup=get_cancel_keyboard())
    elif message.text == "🗂 Проверить файл":
        user_state[user_id] = 'awaiting_file'
        save_action(user_id, "Проверить файл")
        bot.send_message(user_id,
                         "🗂 Жду от тебя файл для проверки.\nЖдать 1-4 минуты ⌛️\n(максимум 20 МБ)\n\n⛔️ /cancel - отменить действие",
                         reply_markup=get_cancel_keyboard())
    elif message.text == "🤓 Задать вопрос ИИ":
        user_state[user_id] = 'awaiting_chat'
        save_action(user_id, "Задать вопрос ИИ")
        bot.send_message(user_id,
                         "🤓 Задавай вопрос, я тебе отвечу.\n\n⛔️ /cancel - отменить действие",
                         reply_markup=get_cancel_keyboard())
    elif message.text == "👀 Почитать о нас":
        reset_state(user_id)
        save_action(user_id, "Почитать о нас")
        bot.send_message(user_id,
                         "🎓 Я дипломный проект студентов Astana IT University\n"
                         "В частности Alikhan Zhuma, Valerii Pankov и Rodion Kuznetsov.\n"
                         "Меня создали, чтобы помочь проверять подозрительные ссылки, номера и файлы 👁")
        bot.send_message(user_id,
                         "😊 Что хотите сделать дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                         reply_markup=get_main_keyboard())
@bot.message_handler(
    func=lambda message: message.text in ["Отменить⛔️", "/cancel"] and user_state.get(message.chat.id) in [
        'awaiting_link', 'awaiting_phone', 'awaiting_chat', 'confirming_phone', 'awaiting_file'])
def cancel_action(message):
    reset_state(message.chat.id)
    save_action(message.chat.id, "/cancel")
    bot.send_message(message.chat.id,
                     "⛔️ Действие отменено! Что дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                     reply_markup=get_main_keyboard())
@bot.message_handler(content_types=['text'])
def handle_text_message(message):
    user_id = message.chat.id
    state = user_state.get(user_id, 'start')
    if state == 'start':
        bot.send_message(user_id,
                         "👋🏻 Привет! Я бот для проверки ссылок, номеров и файлов.\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                         reply_markup=get_main_keyboard())
    elif state == 'awaiting_link':
        link = message.text
        if is_valid_link(link):
            if not link.startswith(('http://', 'https://')):
                link = 'https://' + link
            loading_msg = bot.send_message(user_id, "Проверяю...")
            bot.send_chat_action(user_id, 'typing')
            results[user_id] = None
            threading.Thread(target=animate_link_loading, args=(bot, user_id, loading_msg.message_id)).start()
            results[user_id] = check_link(link)
            stop_flags[user_id] = True
            bot.edit_message_text(results[user_id], user_id, loading_msg.message_id, disable_web_page_preview=True)
            reset_state(user_id)
            bot.send_message(user_id,
                             "😊 Что хотите сделать дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                             reply_markup=get_main_keyboard())
        else:
            bot.send_message(user_id,
                             "🥺 Это не похоже на ссылку.\n\n🔗 Жду подозрительную ссылку.\nЖдать около 15 секунд ⌛️\n\n⛔️ /cancel - отменить действие",
                             reply_markup=get_cancel_keyboard())
    elif state == 'awaiting_phone':
        phone_number = message.text
        user_data[user_id] = {'phone_number': phone_number}
        user_state[user_id] = 'confirming_phone'
        bot.send_message(user_id,
                         f"👀 Номер набран правильно? ({phone_number})\n✅ /yes - да\n⛔️ /no - нет",
                         reply_markup=get_confirm_keyboard())
    elif state == 'confirming_phone':
        phone_number = user_data.get(user_id, {}).get('phone_number', '')
        if message.text in ["Да✅", "/yes"]:
            result = check_phone(phone_number)
            if "error" in result:
                bot.send_message(user_id,
                                 f"{result['error']} (например, +7 707 404 6633).\n\n⛔️ /cancel - отменить действие",
                                 reply_markup=get_cancel_keyboard())
                user_state[user_id] = 'awaiting_phone'
            else:
                bot.send_message(user_id, result, disable_web_page_preview=True)
                reset_state(user_id)
                bot.send_message(user_id,
                                 "😊 Что хотите сделать дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                                 reply_markup=get_main_keyboard())
        elif message.text in ["Нет⛔️", "/no"]:
            user_state[user_id] = 'awaiting_phone'
            bot.send_message(user_id,
                             "☎️ Введите номер заново (например, +7 707 404 6633).\n\n⛔️ /cancel - отменить действие",
                             reply_markup=get_cancel_keyboard())
    elif state == 'awaiting_chat':
        loading_msg = bot.send_message(user_id, "Думаю...")
        bot.send_chat_action(user_id, 'typing')
        results[user_id] = None
        threading.Thread(target=animate_ai_loading, args=(bot, user_id, loading_msg.message_id)).start()
        query = message.text
        results[user_id] = get_ai_response(query)
        stop_flags[user_id] = True
        bot.edit_message_text(results[user_id], user_id, loading_msg.message_id)
        reset_state(user_id)
        bot.send_message(user_id,
                         "😊 Что хотите сделать дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                         reply_markup=get_main_keyboard())
    elif state == 'awaiting_file':
        bot.send_message(user_id,
                         "🥺 Это не файл! Пожалуйста, отправьте файл (документ, фото или видео).\n\n🗂 Жду файл для проверки.\nЖдать 1-4 минуты ⌛️\n(максимум 20 МБ)\n\n⛔️ /cancel - отменить действие",
                         reply_markup=get_cancel_keyboard())
@bot.message_handler(content_types=['document', 'photo', 'video'],
                     func=lambda message: user_state.get(message.chat.id) == 'awaiting_file')
def handle_file(message):
    user_id = message.chat.id
    loading_msg = bot.send_message(user_id, "Проверяю...")
    bot.send_chat_action(user_id, 'typing')
    if message.document and message.document.file_size > 20 * 1024 * 1024:
        bot.edit_message_text("⚠️ Файл слишком большой (максимум 20 МБ)", user_id, loading_msg.message_id)
        reset_state(user_id)
        bot.send_message(user_id,
                         "😊 Что хотите сделать дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                         reply_markup=get_main_keyboard())
        return
    elif message.video and message.video.file_size > 20 * 1024 * 1024:
        bot.edit_message_text("⚠️ Файл слишком большой (максимум 20 МБ)", user_id, loading_msg.message_id)
        reset_state(user_id)
        bot.send_message(user_id,
                         "😊 Что хотите сделать дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                         reply_markup=get_main_keyboard())
        return
    elif message.photo and message.photo[-1].file_size > 20 * 1024 * 1024:
        bot.edit_message_text("⚠️ Файл слишком большой (максимум 20 МБ)", user_id, loading_msg.message_id)
        reset_state(user_id)
        bot.send_message(user_id,
                         "😊 Что хотите сделать дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                         reply_markup=get_main_keyboard())
        return
    results[user_id] = None
    threading.Thread(target=animate_file_loading, args=(bot, user_id, loading_msg.message_id)).start()
    if message.document:
        file_info = bot.get_file(message.document.file_id)
        file_name = message.document.file_name
    elif message.photo:
        file_info = bot.get_file(message.photo[-1].file_id)
        file_name = f"photo_{user_id}.jpg"
    elif message.video:
        file_info = bot.get_file(message.video.file_id)
        file_name = message.video.file_name or f"video_{user_id}.mp4"
    else:
        bot.edit_message_text("Формат файла не поддерживается 🥺", user_id, loading_msg.message_id)
        reset_state(user_id)
        bot.send_message(user_id,
                         "😊 Что хотите сделать дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                         reply_markup=get_main_keyboard())
        return
    file_url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_info.file_path}"
    file_path = f"temp_{user_id}_{file_name}"
    with open(file_path, "wb") as f:
        f.write(requests.get(file_url).content)
    results[user_id] = check_file_with_virustotal(file_path)
    stop_flags[user_id] = True
    bot.edit_message_text(results[user_id], user_id, loading_msg.message_id, disable_web_page_preview=True)
    os.remove(file_path)
    reset_state(user_id)
    bot.send_message(user_id,
                     "😊 Что хотите сделать дальше?\nПроверить ссылку - /link 🔗\nУзнать про номер - /number ☎️\nПроверить файл - /file 🗂\nЗадать вопрос ИИ - /chat 🤓\nПочитать о нас - /about 👀",
                     reply_markup=get_main_keyboard())
@bot.message_handler(content_types=['audio', 'voice', 'sticker', 'video_note', 'contact', 'location'])
def handle_invalid_input(message):
    user_id = message.chat.id
    state = user_state.get(user_id, 'start')
    if state == 'awaiting_link':
        bot.send_message(user_id,
                         "🥺 Это не ссылка! Пожалуйста, отправьте текстовую ссылку.\n\n🔗 Жду подозрительную ссылку.\nЖдать около 15 секунд ⌛️\n\n⛔️ /cancel - отменить действие",
                         reply_markup=get_cancel_keyboard())
    elif state == 'awaiting_phone':
        bot.send_message(user_id,
                         "🥺 Это не номер телефона! Пожалуйста, отправьте текстовый номер (например, +7 707 404 6633).\n\n☎️ Жду от вас номер.\n\n⛔️ /cancel - отменить действие",
                         reply_markup=get_cancel_keyboard())
    elif state == 'awaiting_chat':
        bot.send_message(user_id,
                         "🥺 Это не текст! Пожалуйста, отправьте текстовый вопрос.\n\n🤓 Задавайте вопрос, я отвечу.\n\n⛔️ /cancel - отменить действие",
                         reply_markup=get_cancel_keyboard())
    elif state == 'awaiting_file':
        bot.send_message(user_id,
                         f"🥺 Формат {message.content_type} не поддерживается! Пожалуйста, отправьте документ, фото или видео.\n\n🗂 Жду файл для проверки.\nЖдать 1-4 минуты ⌛️\n(максимум 20 МБ)\n\n⛔️ /cancel - отменить действие",
                         reply_markup=get_cancel_keyboard())
def start_bot():
    while True:
        try:
            logger.info("Бот запущен и ожидает сообщений...")
            bot.polling(none_stop=True)
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Ошибка соединения: {e}. Повторная попытка через 10 секунд...")
            time.sleep(10)
        except Exception as e:
            logger.error(f"Неизвестная ошибка: {e}. Повторная попытка через 10 секунд...")
            time.sleep(10)
if __name__ == "__main__":
    start_bot()