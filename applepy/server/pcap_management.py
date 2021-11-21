import time

from ifcfg import interfaces
from typing import Optional
from fastapi import BackgroundTasks, FastAPI
from scapy.all import sniff, wrpcap
from pydantic import BaseModel
from os import listdir

app = FastAPI()


class CaptureConfig(BaseModel):
    iface: str
    count: int
    filter: Optional[str] = None


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/network-config")
def get_network_config():
    return {"network_config": interfaces()}


@app.post("/packet-capture")
async def start_packet_capture(cap_conf: CaptureConfig, bg_tasks: BackgroundTasks):
    bg_tasks.add_task(sniff_packets,
                      cap_conf.iface, cap_conf.count, cap_conf.filter)

    return {'status': 'task sent'}


@app.get('/pcaps')
def get_pcap_files():
    pcaps = listdir('pcaps')
    return {'pcap_files': pcaps}


def sniff_packets(iface, count, filter):
    pcap = sniff(count=count, iface=iface, filter=filter)
    wrpcap(f'pcaps/packet_capture_{str(time.time()).replace(".", "_")}', pcap)
    return
