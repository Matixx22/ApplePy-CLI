import click
import pandas as pd
import re
from scapy.utils import PcapReader
from applepy.offline.yara_engine import YaraEngine
from flask import Flask, json
from applepy.save_to_log import echo

api = Flask(__name__)

block = False
desc = ""

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


def _detect_sus_file(**kwargs):
    # ciało funkcji - właściwa reguła operująca na danych z args

    description = ""
    rules = {
        'sus_strings': 'yara-rules/suspicious_strings.yar'
    }

    # procesowanie pcap
    for pcap in kwargs['pcap']:
        description = YaraEngine.detect(rules=rules, file=pcap)

    # # procesowanie evtx
    for evtx in kwargs['evtx']:
        description = YaraEngine.detect(rules=rules, file=evtx)

    # # procesowanie xml
    for xml in kwargs['xml']:
        description = YaraEngine.detect(rules=rules, file=xml)

    # # procesowanie json
    for json in kwargs['json']:
        description = YaraEngine.detect(rules=rules, file=json)

    # # procesowanie txt
    for txt in kwargs['txt']:
        description = YaraEngine.detect(rules=rules, file=txt)

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


def _detect_sus_ports(**kwargs):
    description = ''
    # procesowanie pcap
    for csv in kwargs['csv']:
        df = pd.read_csv(csv)
        df1 = df.groupby('Source')['Info'].count()
        df1.to_frame().reset_index()
        sus_ips = []
        sus_ips = df1.nlargest(round(len(df1.index)/2)).reset_index()['Source'].values[:]
        sus_ports = []

        for sus_ip in sus_ips:
            df_sus = df[df['Source'] == sus_ip]
            df_sus['Src port'] = df_sus['Info'].str.extract(r'(^\d*)')
            df_sus2 = df_sus.groupby('Src port')['Info'].count()
            sus_ports.append(df_sus2.reset_index().max().values[0])
            
        description = 'Common ports are ' + ', '.join(sus_ports) + '\n'

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
        

def _find_python_process(**kwargs):
    description = ""
    # ciało funkcji - właściwa reguła operująca na danych z args

    # procesowanie pcap
    # for pcap in kwargs[pcap]:

    # procesowanie evtx
    # for evtx in kwargs[evtx]:

    # procesowanie xml
    # for xml in kwargs["xml"]:

    # procesowanie json
    # for json in kwargs["json"]:


    # procesowanie txt
    for txt in kwargs["txt"]:
        file = open(txt, 'r')
        line_count = 1

        for line in file:
            if re.findall(r'.*\s?python\d*.*\d* *', line):
                description += 'Found: ' + re.findall(r'.*\s?python\d*.*\d* *', line)[0] + f' at line {str(line_count)}\n' 
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


def _detect_dropbox_communication(**kwargs):
    # ciało funkcji - właściwa reguła operująca na danych z args
    description = ""
    ip_list = ['162.125.66.14', '162.125.72.14']
    # procesowanie pcap
    for pcap in kwargs["pcap"]:
        for packet in PcapReader(pcap):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            if src_ip in ip_list:
                description += "Found packet from dropbox IP address " + src_ip + "!\n"
            if dst_ip in ip_list:
                description += "Found packet to dropbox IP address " + dst_ip + "!\n"
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


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-f', '--filenames', help='path to files to analyze', multiple=True)
@click.option('-r', '--rule', help='Specify rule. If leave empty all rules are applied.\
                                    Available rules: c2-ip, virus, sus-file', type=str)
# @click.argument('filenames', multiple=True)
def detect(filenames, rule):
    pcap = []
    evtx = []
    xml = []
    json = []
    txt = []
    csv = []

    output = []

    for filename in filenames:
        extension = filename.split('.')[-1]
        if extension == "cap" or extension == "pcap" or extension == "pcapng":
            pcap.append(filename)
        if extension == "evtx":
            evtx.append(filename)
        if extension == "xml":
            xml.append(filename)
        if extension == "json":
            json.append(filename)
        if extension == "txt":
            txt.append(filename)
        if extension == "csv":
            csv.append(filename)
    if rule is None:
        output.append(_find_virus(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
        output.append(_find_c2_ip(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
        output.append(_detect_sus_file(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
        output.append(_detect_sus_ports(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt, csv=csv))
        output.append(_find_python_process(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
        output.append(_detect_dropbox_communication(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
    if rule == "c2-ip":
        output.append(_find_c2_ip(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
    if rule == "virus":
        output.append(_find_virus(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
    if rule == "sus-file":
        output.append(_detect_sus_file(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
    if rule == "sus-ip":
        output.append(_detect_sus_ports(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt, csv=csv))
    if rule == "python-process":
        output.append(_find_python_process(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))
    if rule == "dropbox-communication":
        output.append(_detect_dropbox_communication(pcap=pcap, evtx=evtx, xml=xml, json=json, txt=txt))

    for action_alert, action_block, description in output:
        echo(description)
        if action_alert == "remote":
            global block
            block = action_block
            global desc
            desc = description
            api.run()


@api.route('/', methods=['GET'])
def get_companies():
    return json.dumps([block, desc.split("\n")])
