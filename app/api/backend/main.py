from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import pandas as pd
import os
import datetime
import sqlite3
import requests
from pydantic import BaseModel

app = FastAPI()

RYU_REST_URL = "http://127.0.0.1:8080"
CSV_FILE = 'traffic_predict.csv'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  
DB_PATH = os.path.join(BASE_DIR, "../../controller/traffic.db")

app.mount("/static", StaticFiles(directory="static"), name="static")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  
    return conn


@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html", "r") as f:
        return f.read()

class BlockRequest(BaseModel):
    dpid: int
    eth_src: str
    eth_dst: str
    in_port: int

def block_traffic_rest(dpid: int, eth_src: str, eth_dst: str, in_port: int):
    flow_rule = {
        "dpid": dpid,
        "priority": 100,
        "match": {
            "in_port": in_port,
            "eth_src": eth_src,
            "eth_dst": eth_dst
        },
        "actions": []  # Nenhuma ação = DROP
    }

    try:
        response = requests.post("{}/stats/flowentry/add".format(RYU_REST_URL), json=flow_rule)
        if response.status_code == 200:
            return {"status": "success", "message": "Tráfego bloqueado com sucesso."}
        else:
            return {"status": "error", "message": "Erro do Ryu: {}".format(response.text)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/block")
def block_flow(request: BlockRequest):
    result = block_traffic_rest(
        dpid=request.dpid,
        eth_src=request.eth_src,
        eth_dst=request.eth_dst,
        in_port=request.in_port
    )

    if result["status"] == "success":
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO blocked_flows (dpid, eth_src, eth_dst, in_port, timestamp) VALUES (?, ?, ?, ?, ?)",
            (request.dpid, request.eth_src, request.eth_dst, request.in_port, datetime.datetime.now().timestamp())
        )
        conn.commit()
        conn.close()

        if not hasattr(app.state, "rules_active"):
            app.state.rules_active = 0
        app.state.rules_active += 1

    return result

@app.get("/api/traffic")
def get_traffic():
    conn = get_db_connection()
    df = conn.execute("SELECT dpid, eth_src, eth_dst, in_port, bytes, time FROM flows").fetchall()
    conn.close()

    if not df:
        return {"error": "No traffic data available."}

    df = [dict(row) for row in df]
    for row in df:
        row["timestamp"] = datetime.datetime.fromtimestamp(row["time"]).strftime('%H:%M:%S')

    aggregated = {}
    timestamps = sorted(set(row["timestamp"] for row in df))
    for row in df:
        dpid = row["dpid"]
        ts = row["timestamp"]
        if dpid not in aggregated:
            aggregated[dpid] = {t: 0 for t in timestamps}
        aggregated[dpid][ts] += row["bytes"]

    datasets = []
    for dpid, traffic_data in aggregated.items():
        datasets.append({
            "label": f"Switch {dpid}",
            "data": [traffic_data[t] for t in timestamps],
            "fill": False,
            "borderColor": f"#{hash(str(dpid)) & 0xFFFFFF:06x}",
            "tension": 0.1
        })

    return {"labels": timestamps, "datasets": datasets}

@app.get("/api/overview")
def get_network_overview():
    try:
        switches_resp = requests.get("{}/v1.0/topology/switches".format(RYU_REST_URL))
        hosts_resp = requests.get("{}/v1.0/topology/hosts".format(RYU_REST_URL))

        switches_resp.raise_for_status()
        hosts_resp.raise_for_status()

        switches = switches_resp.json()
        hosts = hosts_resp.json()

        return {
            "switches": len(switches),
            "hosts": len(hosts)
        }
    except Exception as e:
        return {"error": "Falha ao obter dados do Ryu: {}".format(str(e))}



@app.get("/api/switches")
def get_switches():
    try:
        response = requests.get("{}/stats/switches".format(RYU_REST_URL))
        response.raise_for_status()
        switches = response.json()
        return {"switches": switches}
    except Exception as e:
        return {"error": "Falha ao obter switches do Ryu: {}".format(str(e))}

@app.get("/api/hosts")
def get_hosts():
    try:
        response = requests.get("{}/v1.0/topology/hosts".format(RYU_REST_URL))
        response.raise_for_status()
        hosts = response.json()
        return {"hosts": [{"mac": h.get("mac", "N/A")} for h in hosts]}
    except Exception as e:
        return {"error": "Falha ao obter hosts do Ryu: {}".format(str(e))}
    
@app.get("/api/stats")
def get_stats():
    conn = get_db_connection()
    rows = conn.execute("SELECT label FROM flows").fetchall()
    conn.close()

    total = len(rows)
    suspicious = sum(1 for row in rows if row["label"] == 1) if rows else 0
    legitimate = total - suspicious
    legitimate_pct = round((legitimate / total) * 100, 1) if total > 0 else 100.0
    attacks_detected = suspicious
    rules_active = getattr(app.state, "rules_active", 0)

    return {
        "attacks_detected": attacks_detected,
        "suspicious_traffic": suspicious,
        "legitimate_traffic_pct": legitimate_pct,
        "rules_active": rules_active
    }


@app.get("/api/alerts")
def get_recent_alerts(limit: int = 5):
    conn = get_db_connection()
    rows = conn.execute("SELECT eth_src, eth_dst, in_port, time FROM flows WHERE label = 1 ORDER BY time DESC LIMIT ?", (limit,)).fetchall()
    conn.close()

    alerts = [{"source": r["eth_src"], "destination": r["eth_dst"], "port": r["in_port"], "time": r["time"]} for r in rows]
    return {"alerts": alerts}
