import time
import subprocess

from ifcfg import interfaces
from typing import Optional
from fastapi import BackgroundTasks, FastAPI
from fastapi.responses import FileResponse
from scapy.all import sniff, wrpcap
from pydantic import BaseModel
from os import listdir
from os.path import isfile, join

app = FastAPI()


class CaptureConfig(BaseModel):
    iface: str
    count: int
    filter: Optional[str] = None


class Command(BaseModel):
    cmd: str
    args: Optional[str] = None


@app.get("/")
async def read_root():
    return {"Hello": "World"}

# PCAP
################################################


@app.get("/network-config")
async def get_network_config():
    return {"network_config": interfaces()}


@app.post("/packet-capture")
async def start_packet_capture(cap_conf: CaptureConfig, bg_tasks: BackgroundTasks):
    bg_tasks.add_task(sniff_packets,
                      cap_conf.iface, cap_conf.count, cap_conf.filter)

    return {'status': 'task sent'}


@app.get('/pcaps')
async def get_pcap_files():
    pcaps = listdir('pcaps')
    return {'pcap_files': pcaps}


@app.get('/pcaps/{file_id}', response_class=FileResponse)
async def get_pcap_file(file_id: int):
    pcaps = listdir('pcaps')
    pcap_to_download = f'pcaps/{pcaps[file_id]}'
    return pcap_to_download


def sniff_packets(iface, count, filter):
    pcap = sniff(count=count, iface=iface, filter=filter)
    wrpcap(f'pcaps/packet_capture_{str(time.time()).replace(".", "_")}', pcap)
    return

# LOG
################################################


@app.get('/logs')
async def get_log_files():
    log_path = '/var/log/'
    log_files = [f for f in listdir(log_path) if isfile(join(log_path, f))]
    return {'log_files': log_files}


@app.get('/logs/{file_id}', response_class=FileResponse)
async def get_log_file(file_id: int):
    log_path = '/var/log/'
    log_files = [f for f in listdir(log_path) if isfile(join(log_path, f))]
    log_to_download = log_path + log_files[file_id]
    return log_to_download

# CMD
################################################


@app.post('/cmd')
async def run_command(cmd: Command):
    full_command = []
    full_command.append(cmd.cmd)
    if cmd.args is not None:
        full_command.extend(cmd.args.split(' '))
    result = subprocess.run(full_command, capture_output=True)
    return {'result': result}
