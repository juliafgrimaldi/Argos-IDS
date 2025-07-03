from fastapi import FastAPI
import socketio
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import pandas as pd
import os
import datetime
import socket
import requests

app = FastAPI()

RYU_REST_URL = "http://127.0.0.1:8080/stats/flowentry/add"
CSV_FILE = 'traffic_predict.csv'

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html", "r") as f:
        return f.read()

def block_traffic_rest(dpid: int, eth_src: str, eth_dst: str, in_port: int):
    flow_rule = {
        "dpid": dpid,
        "priority": 100,
        "match": {
            "in_port": in_port,
            "eth_src": eth_src,
            "eth_dst": eth_dst
        },
        "actions": []
    }
    response = requests.post(RYU_REST_URL, json=flow_rule)
    if response.status_code == 200:
        return {"status": "success", "message": "Traffic blocked"}
    else:
        return {"status": "error", "message": response.text}

@app.get("/block/{dpid}/{src}/{dst}/{port}")
def block_flow(dpid: int, src: str, dst: str, port: int):
    result = block_traffic_rest(dpid, src, dst, port)
    return result


@app.get("/api/traffic")
def get_traffic():
    if not os.path.exists(CSV_FILE):
        return {"error": "Arquivo CSV não encontrado."}

    df = pd.read_csv(CSV_FILE)

    if 'time' not in df.columns or 'dpid' not in df.columns or 'bytes' not in df.columns:
        return {"error": "CSV deve conter as colunas: time, dpid, bytes"}

    # Converte o timestamp UNIX para datetime legível
    df['timestamp'] = df['time'].apply(lambda ts: datetime.datetime.fromtimestamp(float(ts)).strftime('%H:%M:%S'))

    grouped = df.groupby(['dpid', 'timestamp'])['bytes'].sum().reset_index()

    # Eixo X: todos os tempos únicos ordenados
    timestamps = sorted(grouped['timestamp'].unique().tolist())

    datasets = []
    for dpid in grouped['dpid'].unique():
        switch_data = grouped[grouped['dpid'] == dpid]
        traffic_per_time = switch_data.set_index('timestamp')['bytes'].reindex(timestamps, fill_value=0)

        datasets.append({
            "label": f"Switch {dpid}",
            "data": traffic_per_time.tolist(),
            "fill": False,
            "borderColor": f"#{hash(str(dpid)) & 0xFFFFFF:06x}",
            "tension": 0.1
        })

    return {
        "labels": timestamps,
        "datasets": datasets
    }

@app.get("/api/overview")
def get_network_overview():
    if not os.path.exists(CSV_FILE):
        return {"error": "Arquivo CSV não encontrado."}

    df = pd.read_csv(CSV_FILE)

    num_switches = df['dpid'].nunique()
    num_hosts = df['eth_src'].nunique()

    return {
        "switches": num_switches,
        "hosts": num_hosts
    }

@app.get("/api/switches")
def get_switches():
    if not os.path.exists(CSV_FILE):
        return {"error": "Arquivo CSV não encontrado."}

    df = pd.read_csv(CSV_FILE)
    switches = df['dpid'].dropna().unique().tolist()

    return {"switches": switches}


