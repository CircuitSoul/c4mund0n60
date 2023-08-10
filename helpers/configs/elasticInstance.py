def getURLBase():
    with open('configuration/config.txt') as configFile:
        for configLine in configFile:
            try:
                if('ELASTIC_URLBASE' in configLine):
                    return (configLine.rstrip('\n').split('"')[1])
            except:
                pass
def getUser():
    with open('configuration/config.txt') as configFile:
        for configLine in configFile:
            try:
                if('ELASTIC_USER' in configLine):
                    return (configLine.rstrip('\n').split('"')[1])
            except:
                pass
def getPass():
    with open('configuration/config.txt') as configFile:
        for configLine in configFile:
            try:
                if('ELASTIC_PASS' in configLine):
                    return (configLine.rstrip('\n').split('"')[1])
            except:
                pass