def getVTAPIKEY():
    with open('configuration/config.txt') as configFile:
        for configLine in configFile:
            try:
                if('VTAPIKEY' in configLine):
                    return (configLine.rstrip('\n').split('"')[1])
            except:
                pass
def getCHAOSKEY():
    with open('configuration/config.txt') as configFile:
        for configLine in configFile:
            try:
                if('CHAOSKEY' in configLine):
                    return (configLine.rstrip('\n').split('"')[1])
            except:
                pass