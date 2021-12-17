

def nazwa_funkcji_reguly(**kwargs):
    # ciało funkcji - właściwa reguła operująca na danych z args
    # procesowanie pcap
    # for pcap in kwargs[pcap]:
    # procesowanie evtx
    # for evtx in kwargs[evtx]:
    # procesowanie xml
    # for xml in kwargs[xml]:
    # procesowanie json
    # for json in kwargs[json]:
    # procesowanie txt
    # for txt in kwargs[txt]:
    # ostateczna reguła - tj. co ma się wykonać
    if condition=True:
        action_alert = "..." # akcja: "local", "remote"
        action_block = True # or False
        description = "Alert ..." # format w OFF.8.5
    else:
        action_alert = None
        action_block = None
        description = None
    return action_alert, action_block, description