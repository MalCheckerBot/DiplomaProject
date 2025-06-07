const { default: makeWASocket, DisconnectReason, useMultiFileAuthState } = require('baileys');
const axios = require('axios');
const qrcode = require('qrcode-terminal');
const cheerio = require('cheerio');
const keys = require('./keys.json');
const VIRUSTOTAL_API_KEY = keys.VIRUSTOTAL_API_KEY;
const GOOGLE_SAFE_BROWSING_API_KEY = keys.GOOGLE_SAFE_BROWSING_API_KEY;
const AIML_API_KEY = keys.AIML_API_KEY;
const AIML_API_URL = keys.AIML_API_URL;
const userState = {};
const userData = {};
const lastMessageTime = {};
const MESSAGE_COOLDOWN = 1000;
function isValidLink(text) {
    const domainPattern = /^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/;
    return Boolean(text.match(domainPattern));
}
function getMainMenu() {
    return '👋🏻 Привет! Я бот для проверки ссылок, номеров и файлов.\n🔗 Проверить ссылку - 1\n☎️ Узнать про номер - 2\n🤓 Задать вопрос ИИ - 3\n👀 Почитать о нас - 4';
}
async function checkLink(url) {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }
    const vtResult = await checkWithVirusTotal(url);
    const vtMessage = `🦠 VirusTotal:\n${vtResult.error ? vtResult.error : `Угрозы: ${vtResult.malicious}/${vtResult.total_engines} ⚠️\nОтчёт: ${vtResult.report_url}`}`;
    const saResult = await checkWithScamAdviser(url);
    const saMessage = `☄️ ScamAdviser:\n${saResult.error ? saResult.error : `Уровень доверия: ${saResult.trust_score} / 100 ⭐\nОтчёт: ${saResult.report_url}`}`;
    const gsbResult = await checkWithGoogleSafeBrowsing(url);
    const gsbMessage = `☁️ Google Safe Browsing:\n${gsbResult.error ? gsbResult.error : gsbResult.is_safe ? `Ссылка безопасна ✅` : `Найдены угрозы: ${gsbResult.threats.join(`, `)} ⚠️`}`;
    let result = `${vtMessage}\n\n${saMessage}\n\n${gsbMessage}`;
    let isDangerous = false;
    let isSafe = true;
    if (!vtResult.error && vtResult.malicious > 0) {
        isDangerous = true;
        isSafe = false;
    }
    if (!saResult.error && parseInt(saResult.trust_score) < 75) {
        isDangerous = true;
        isSafe = false;
    }
    if (!gsbResult.error && !gsbResult.is_safe) {
        isDangerous = true;
        isSafe = false;
    }
    if (isDangerous) {
        result += '\n\n📝 Итог:\nДанная ссылка - Потенциально Вредоносная.\nНе рекомендую её открывать❗️';
    } else if (isSafe) {
        result += '\n\n📝 Итог:\nДанная ссылка - Безопасна ✅';
    }
    return result;
}
async function checkWithVirusTotal(url) {
    const encodedUrl = Buffer.from(url).toString('base64url').replace(/=+$/, '');
    const reportUrl = `https://www.virustotal.com/gui/url/${encodedUrl}/detection`;
    try {
        const scanResponse = await axios.post('https://www.virustotal.com/api/v3/urls', new URLSearchParams({ url }).toString(), {
            headers: {
                'x-apikey': VIRUSTOTAL_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        if (scanResponse.status !== 200) {
            return { error: 'Ошибка VirusTotal.\nПопробуйте ещё раз 🥺' };
        }
        const analysisId = scanResponse.data.data.id;
        while (true) {
            const analysisResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
            });
            const status = analysisResponse.data.data.attributes.status;
            if (status === 'completed') {
                const stats = analysisResponse.data.data.attributes.stats;
                const totalEngines = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
                return { malicious: stats.malicious, total_engines: totalEngines, report_url: reportUrl };
            } else if (status === 'queued') {
                await new Promise(resolve => setTimeout(resolve, 10000));
            } else {
                return { error: 'Ошибка, статус анализа VirusTotal.\nПопробуйте ещё раз 🥺' };
            }
        }
    } catch (e) {
        console.error(`VirusTotal error: ${e.message}, Code: ${e.code}, Response: ${JSON.stringify(e.response?.data)}`);
        return { error: 'Ошибка VirusTotal.\nПопробуйте ещё раз 🥺' };
    }
}
async function checkWithScamAdviser(url) {
    try {
        const domain = url.split('//')[1].split('/')[0];
        const reportUrl = `https://www.scamadviser.com/check-website/${domain}`;
        const response = await axios.get(reportUrl);
        if (response.status === 200) {
            const $ = cheerio.load(response.data);
            const trustScore = $('div#trustscore').attr('data-rating');
            if (trustScore) {
                return { trust_score: trustScore.trim(), report_url: reportUrl };
            }
            return { error: 'Ошибка, уровень доверия не найден.\nПопробуйте ещё раз 🥺' };
        } else {
            return { error: 'Ошибка запроса к ScamAdviser.\nПопробуйте ещё раз 🥺' };
        }
    } catch (e) {
        return { error: 'Ошибка парсинга ScamAdviser.\nПопробуйте ещё раз 🥺' };
    }
}
async function checkWithGoogleSafeBrowsing(url) {
    try {
        const response = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`, {
            client: { clientId: 'your-client-id', clientVersion: '1.0' },
            threatInfo: {
                threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                platformTypes: ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries: [{ url }]
            }
        });
        if (response.data.matches) {
            return { threats: response.data.matches.map(m => m.threatType), is_safe: false };
        }
        return { threats: [], is_safe: true };
    } catch (e) {
        return { error: 'Ошибка при проверке через Google Safe Browsing.\nПопробуйте ещё раз 🥺' };
    }
}
async function checkPhone(phoneNumber) {
    const cleanedNumber = phoneNumber.trim().replace(/[()\-\s]+/g, '').replace(/^8/, '+7');
    if (!cleanedNumber.startsWith('+') || !/^\+\d+$/.test(cleanedNumber)) {
        return '☎️ Номер должен начинаться с плюса (+) и содержать только цифры.\nПопробуйте ещё раз 🥺';
    }
    try {
        const response = await axios.get(`https://spamcalls.net/en/search?q=${cleanedNumber}`, {
            timeout: 20000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            },
            proxy: {
                protocol: keys.proxy.protocol,
                host: keys.proxy.host,
                port: keys.proxy.port,
                auth: {
                    username: keys.proxy.username,
                    password: keys.proxy.password
                }
            }
        });
        if (response.status === 200) {
            const $ = cheerio.load(response.data);
            const title = $('h1').text();
            if (title && cleanedNumber.includes(title)) {
                const details = {};
                $('div.col-lg-12.clickable-scroll-to').each((_, block) => {
                    const h3 = $(block).find('h3').text().trim();
                    if (h3) {
                        const key = h3.includes('Most frequently reported') ? 'Most frequently reported' : h3;
                        const value = $(block).find('h4').text().trim() || 'Информация отсутствует.';
                        details[key] = value;
                    }
                });
                let detailsMessage = '';
                if (details['Spam-Risk']) detailsMessage += `Уровень Спама: ${details[`Spam-Risk`]}\n`;
                if (details['Country of origin']) detailsMessage += `Страна происхождения: ${details[`Country of origin`]}\n`;
                if (details['Most frequently reported']) detailsMessage += `Чаще всего жалуются на: ${details[`Most frequently reported`]}\n`;
                const reportUrl = `https://spamcalls.net/en/search?q=${cleanedNumber}`;
                if (details['Spam-Risk'] || details['Most frequently reported']) {
                    return `⚠️ Номер ${cleanedNumber} отмечен как спам или мошенничество.\n\n🔎 Детали:\n${detailsMessage}\n📝 Отчёт: ${reportUrl}`;
                } else {
                    return `✅ Номер ${cleanedNumber} безопасен.\n\n📝 Отчёт: ${reportUrl}`;
                }
            } else {
                return `✅ Номер ${cleanedNumber} безопасен.\n\n📝 Отчёт: ${reportUrl}`;
            }
        } else {
            console.error(`SpamCalls error: HTTP ${response.status}`);
            return '⚠️ Ошибка запроса к SpamCalls.\nПопробуйте ещё раз 🥺';
        }
    } catch (e) {
        console.error(`SpamCalls error: ${e.message}, Code: ${e.code}, Response: ${JSON.stringify(e.response?.data)}`);
        return '⚠️ Ошибка при проверке через SpamCalls.\nПопробуйте ещё раз 🥺';
    }
}
async function getAIResponse(query) {
    try {
        const response = await axios.post(AIML_API_URL, {
            model: 'gpt-3.5-turbo-instruct',
            prompt: `Давай краткие ответы в 2-3 предложения, максимум 200 символов. Если вопрос не по теме кибербезопасности, мошенничества и так далее, скажи: 'Извини, я отвечаю только на вопросы про кибербезопасность и мошенничество.' Если вопрос неясен или неполный, отвечай: 'Извини, я не понял твой вопрос. Задай его точнее, пожалуйста!' Вот вопрос: ${query}`,
            max_tokens: 200,
            temperature: 0.3
        }, {
            headers: { 'Authorization': `Bearer ${AIML_API_KEY}`, 'Content-Type': 'application/json' },
            timeout: 20000,
            proxy: {
                protocol: keys.proxy.protocol,
                host: keys.proxy.host,
                port: keys.proxy.port,
                auth: {
                    username: keys.proxy.username,
                    password: keys.proxy.password
                }
            }
        });
        const cleanText = response.data.choices[0].text.trim().replace(/\n\n/g, ' ').replace(/\n/g, ' ');
        return `🤓 Ответ:\n${cleanText}`;
    } catch (e) {
        console.error(`AI error: ${e.message}, Code: ${e.code}, URL: ${e.config?.url}, Headers: ${JSON.stringify(e.config?.headers)}, Response: ${JSON.stringify(e.response?.data)}, FullError: ${JSON.stringify(e, Object.getOwnPropertyNames(e))}`);
        return '⚠️ Что-то пошло не так с ИИ.\nПопробуйте ещё раз 🥺';
    }
}
async function startWhatsAppBot() {
    const { state, saveCreds } = await useMultiFileAuthState('auth_info');
    const sock = makeWASocket({
        auth: state,
        printQRInTerminal: true,
        generateLinkPreview: false,
        generateHighQualityLinkPreview: false
    });
    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect, qr } = update;
        if (qr) {
            console.log('QR code received, please scan it:');
            qrcode.generate(qr, { small: true });
        }
        if (connection === 'close') {
            if (lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut) {
                startWhatsAppBot();
            } else {
                console.log('Logged out, please scan QR again.');
            }
        } else if (connection === 'open') {
            console.log('WhatsApp connected!');
        }
    });
    sock.ev.on('creds.update', saveCreds);
    sock.ev.on('messages.upsert', async ({ messages }) => {
        const msg = messages[0];
        if (!msg.message || msg.key.fromMe) return;
        const from = msg.key.remoteJid;
        const userId = from.split('@')[0];
        const now = Date.now();
        if (lastMessageTime[userId] && now - lastMessageTime[userId] < MESSAGE_COOLDOWN) return;
        lastMessageTime[userId] = now;
        if (!userState[userId]) userState[userId] = 'start';
        const text = (msg.message.conversation || msg.message.extendedTextMessage?.text || '').toLowerCase();
        const originalText = msg.message.conversation || msg.message.extendedTextMessage?.text || '';
        if (text === '1') {
            userState[userId] = 'awaiting_link';
            await sock.sendMessage(from, { text: '🔗 Жду подозрительную ссылку.\nЖдать около 15 секунд ⌛️\n\n⛔️ Отмена - отменить действие' });
        } else if (text === '2') {
            userState[userId] = 'awaiting_phone';
            await sock.sendMessage(from, { text: '☎️ Жду от тебя номер (например, +7 707 404 6633).\n\n⛔️ Отмена - отменить действие' });
        } else if (text === '3') {
            userState[userId] = 'awaiting_chat';
            await sock.sendMessage(from, { text: '🤓 Задавай вопрос, я тебе отвечу.\n\n⛔️ Отмена - отменить действие' });
        } else if (text === '4') {
            userState[userId] = 'start';
            delete userData[userId];
            await sock.sendMessage(from, { text: '🎓 Я дипломный проект студентов Astana IT University\nВ частности Alikhan Zhuma, Valerii Pankov и Rodion Kuznetsov.\nМеня создали, чтобы помочь проверять подозрительные ссылки, номера и файлы 👁' });
            await sock.sendMessage(from, { text: getMainMenu() });
        } else if (text === 'отмена' && ['awaiting_link', 'awaiting_phone', 'awaiting_chat', 'confirming_phone'].includes(userState[userId])) {
            userState[userId] = 'start';
            delete userData[userId];
            await sock.sendMessage(from, { text: '⛔️ Действие отменено! Что дальше?\n' + getMainMenu() });
        } else if (userState[userId] === 'awaiting_link') {
            const link = isValidLink(originalText) ? (originalText.startsWith('http') ? originalText : 'https://' + originalText) : null;
            if (link) {
                await sock.sendMessage(from, { text: 'Проверяю...🔍✨🔮' });
                const result = await checkLink(link);
                await sock.sendMessage(from, { text: result });
                userState[userId] = 'start';
                delete userData[userId];
                await sock.sendMessage(from, { text: getMainMenu() });
            } else {
                await sock.sendMessage(from, { text: '🥺 Это не похоже на ссылку.\n\n🔗 Жду подозрительную ссылку.\nЖдать около 15 секунд ⌛️\n\n⛔️ Отмена - отменить действие' });
            }
        } else if (userState[userId] === 'awaiting_phone') {
            userData[userId] = { phone_number: originalText };
            userState[userId] = 'confirming_phone';
            await sock.sendMessage(from, { text: `👀 Номер набран правильно? (${originalText})\n✅ "Да" - да\n⛔️ "Нет" - нет.` });
        } else if (userState[userId] === 'confirming_phone') {
            const phoneNumber = userData[userId].phone_number;
            if (text === 'да') {
                const result = await checkPhone(phoneNumber);
                await sock.sendMessage(from, { text: result });
                userState[userId] = 'start';
                delete userData[userId];
                await sock.sendMessage(from, { text: getMainMenu() });
            } else if (text === 'нет') {
                userState[userId] = 'awaiting_phone';
                await sock.sendMessage(from, { text: '☎️ Жду от тебя номер (например, +7 707 404 6633).\n\n⛔️ Отмена - отменить действие' });
            } else {
                await sock.sendMessage(from, { text: `👀 Номер набран правильно? (${originalText})\n✅ "Да" - да\n⛔️ "Нет" - нет.` });
            }
        } else if (userState[userId] === 'awaiting_chat') {
            await sock.sendMessage(from, { text: 'Думаю...🔍✨🔮' });
            const result = await getAIResponse(originalText);
            await sock.sendMessage(from, { text: result });
            userState[userId] = 'start';
            delete userData[userId];
            await sock.sendMessage(from, { text: getMainMenu() });
        } else {
            await sock.sendMessage(from, { text: getMainMenu() });
        }
    });
}
startWhatsAppBot();