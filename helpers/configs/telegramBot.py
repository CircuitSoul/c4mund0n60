import telegram

def getApiToken():
    with open('configuration/config.txt') as configFile:
        for configLine in configFile:
            try:
                if('TELEGRAM_ApiToken' in configLine):
                    return (configLine.rstrip('\n').split('"')[1])
            except:
                pass
def getChatId():
    with open('configuration/config.txt') as configFile:
        for configLine in configFile:
            try:
                if('TELEGRAM_chatID' in configLine):
                    return (configLine.rstrip('\n').split('"')[1])
            except:
                pass
def telegramNotification(message):
    bot = telegram.Bot(token=getApiToken())
    bot.sendMessage(text=message, chat_id=getChatId())