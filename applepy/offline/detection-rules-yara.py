from yara_engine import YaraEngine

def detect_lmn(**kwargs):
    # ciało funkcji - właściwa reguła operująca na danych z args

    # procesowanie pcap
    # for pcap in kwargs[pcap]:
    #     pass

    # # procesowanie evtx
    # for evtx in kwargs[evtx]:
    #     pass

    # # procesowanie xml
    # for xml in kwargs[xml]:
    #     pass

    # # procesowanie json
    # for json in kwargs[json]:
    #     pass

    # # procesowanie txt
    # for txt in kwargs[txt]:
    #     pass

    rules = {
        'sus_strings': 'yara-rules/suspicious_strings.yar'
    }

    for key, item in kwargs.items():
        if key == 'filepath':
            filepath = item

    YaraEngine.detect(rules=rules, file=filepath)

    # ostateczna reguła - tj. co ma się wykonać
    # if condition=True:
    #     action_alert = "..." # akcja: "local", "remote"
    #     action_block = True # or False
    #     description = "Alert ..." # format w OFF.8.5
    # else:
    #     action_alert = None
    #     action_block = None
    #     description = None

    # return action_alert, action_block, description

    # TODO: Robienie alertow, akcji i opisu, to co w lab 1a

detect_lmn(filepath='../test_files/yara_sample.txt')