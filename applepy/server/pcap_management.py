import time
import multiprocessing

from ifcfg import interfaces
from typing import Optional
from fastapi import FastAPI
from scapy.all import sniff, wrpcap
from pydantic import BaseModel

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
def start_packet_capture(cap_conf: CaptureConfig):
    process = multiprocessing.Process(
        target=sniff_packets, args=(cap_conf.iface, cap_conf.count, cap_conf.filter,))
    process.start()

    return {'status': 'sent'}


def sniff_packets(iface, count, filter):
    pcap = sniff(count=count, iface=iface, filter=filter)
    wrpcap(f'pcaps/packet_capture_{str(time.time()).replace(".", "_")}', pcap)
    return
