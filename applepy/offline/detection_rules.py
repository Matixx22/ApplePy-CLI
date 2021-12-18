import click
from scapy.utils import PcapReader

from applepy.save_to_log import echo

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
C2_IP_LIST = ["128.61.240.205"]


def _find_c2_ip(**kwargs):
    # ciało funkcji - właściwa reguła operująca na danych z args
    description = ""
    # procesowanie pcap
    for pcap in kwargs["pcap"]:
        for packet in PcapReader(pcap):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            if src_ip in C2_IP_LIST:
                description += "Found packet from suspicious IP address " + src_ip + "!\n"
            if dst_ip in C2_IP_LIST:
                description += "Found packet to suspicious IP address " + dst_ip + "!\n"
    # procesowanie evtx
    # for evtx in kwargs[evtx]:
    # procesowanie xml
    # for xml in kwargs[xml]:
    # procesowanie json
    # for json in kwargs[json]:
    # procesowanie txt
    # for txt in kwargs[txt]:
    # ostateczna reguła - tj. co ma się wykonać
    if len(description) > 0:
        action_alert = "remote"
        action_block = True
        description = description
    else:
        action_alert = None
        action_block = None
        description = None
    return action_alert, action_block, description


def _find_virus(**kwargs):
    description = ""
    # ciało funkcji - właściwa reguła operująca na danych z args

    # procesowanie pcap
    # for pcap in kwargs[pcap]:

    # procesowanie evtx
    # for evtx in kwargs[evtx]:

    # procesowanie xml
    for xml in kwargs["xml"]:
        file = open(xml, 'r')
        line_count = 1
        for line in file:
            if str.lower(line).find("virus") >= 0:
                description += "Found virus in file " + xml + " line " + str(line_count) + "!\n"
            line_count += 1

    # procesowanie json
    for json in kwargs["json"]:
        file = open(json, 'r')
        line_count = 1
        for line in file:
            if str.lower(line).find("virus") >= 0:
                description += "Found virus in file " + json + " line " + str(line_count) + "!\n"
            line_count += 1

    # procesowanie txt
    for txt in kwargs["txt"]:
        file = open(txt, 'r')
        line_count = 1
        for line in file:
            if str.lower(line).find("virus") >= 0:
                description += "Found virus in file " + txt + " line " + str(line_count) + "!\n"
            line_count += 1

    # ostateczna reguła - tj. co ma się wykonać
    if len(description) > 0:
        action_alert = "local"
        action_block = True
        description = description
    else:
        action_alert = None
        action_block = None
        description = None
    return action_alert, action_block, description


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-f', '--filenames', help='path to files to analyze', multiple=True)
@click.option('-r', '--rule', help='Specify rule. If leave empty all rules are applied', type=str)
# @click.argument('filenames', multiple=True)
def detect(filenames, rule):
    pcap = []
    evtx = []
    xml = []
    json = []
    txt = []

    output = []

    for filename in filenames:
        extension = filename.split('.')[-1]
        if extension == "cap" or extension == "pcap":
            pcap.append(filename)
        if extension == "evtx":
            evtx.append(filename)
        if extension == "xml":
            xml.append(filename)
        if extension == "json":
            json.append(filename)
        if extension == "txt":
            txt.append(filename)
    if rule is None:
        output.append(_find_virus(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
        output.append(_find_c2_ip(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
    if rule == "c2-ip":
        output.append(_find_c2_ip(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
    if rule == "virus":
        output.append(_find_virus(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))

    print(output[0][2])
    for action_alert, action_block, description in output:
        echo(description)


