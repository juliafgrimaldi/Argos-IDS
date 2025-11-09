from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi import Request
import pandas as pd
import os
import datetime
import sqlite3
import requests
import json
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

RYU_REST_URL = "http://127.0.0.1:8080"
CSV_FILE = 'traffic_predict.csv'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  
DB_PATH = os.path.join(BASE_DIR, "../../../controller/traffic.db")
CONFIG_FILE = os.path.join(BASE_DIR, "mitigation_mode.json")

class ContactUpdateRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    enabled: Optional[bool] = None

class ContactRequest(BaseModel):
    name: str
    email: str
    enabled: bool

app.mount("/static", StaticFiles(directory="static"), name="static")

if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w") as f:
        json.dump({"mode": "block"}, f)

@app.post("/api/config/mode")
async def set_mitigation_mode(request: Request):
    try:
        data = await request.json()
        mode = data.get("mode", "").lower().strip()
        if mode not in ["block", "alert"]:
            return {"status": "error", "message": "Modo inválido. Use 'block' ou 'alert'."}

        with open(CONFIG_FILE, "w") as f:
            json.dump({"mode": mode}, f)

        return {"status": "success", "message": f"Modo de mitigação alterado para {mode.upper()}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/config/mode")
def get_mitigation_mode():
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
        return {"mode": data.get("mode", "block")}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  
    return conn

def init_blocked_table():
    """Cria tabela de bloqueios se não existir"""
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dpid INTEGER NOT NULL,
            ip_src TEXT NOT NULL,
            ip_dst TEXT NOT NULL,
            timestamp REAL NOT NULL,
            reason TEXT DEFAULT 'Manual block',
            active BOOLEAN DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()

init_blocked_table()

def init_contacts_table():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            enabled BOOLEAN DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()

init_contacts_table()

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html", "r") as f:
        return f.read()

class BlockRequest(BaseModel):
    dpid: int
    ip_src: str
    ip_dst: str

def block_traffic_rest(dpid: int, ip_src: str, ip_dst: str, reason: str = "Manual block"):
    flow_rule = {
        "dpid": dpid,
        "priority": 65535,
        "match": {
            "eth_type": 2048,        
            "ipv4_src": ip_src,
            "ipv4_dst": ip_dst
        },
        "actions": []  
    }

    try:
        response = requests.post(f"{RYU_REST_URL}/stats/flowentry/add", json=flow_rule, timeout=5)
        if response.status_code == 200:
            # Salvar no banco
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO blocked_flows (dpid, ip_src, ip_dst, timestamp, reason, active) VALUES (?, ?, ?, ?, ?, ?)",
                (dpid, ip_src, ip_dst, datetime.datetime.now().timestamp(), reason, 1)
            )
            conn.commit()
            conn.close()
            
            return {"status": "success", "message": f"Bloqueado: {ip_src} → {ip_dst}"}
        else:
            return {"status": "error", "message": f"Erro do Ryu: {response.text}"}
    except requests.exceptions.Timeout:
        return {"status": "error", "message": "Timeout ao conectar no Ryu"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def unblock_traffic_rest(dpid: int, ip_src: str, ip_dst: str):
    flow_rule = {
        "dpid": dpid,
        "priority": 65535,
        "match": {
            "eth_type": 2048,
            "ipv4_src": ip_src,
            "ipv4_dst": ip_dst
        }
    }

    try:
        response = requests.post(f"{RYU_REST_URL}/stats/flowentry/delete_strict", json=flow_rule, timeout=5)
        if response.status_code == 200:
            # Marcar como inativo no banco
            conn = get_db_connection()
            conn.execute(
                "UPDATE blocked_flows SET active = 0 WHERE dpid = ? AND ip_src = ? AND ip_dst = ? AND active = 1",
                (dpid, ip_src, ip_dst)
            )
            conn.commit()
            conn.close()
            
            return {"status": "success", "message": f"🔓 Desbloqueado: {ip_src} → {ip_dst}"}
        else:
            return {"status": "error", "message": f"Erro do Ryu: {response.text}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/block")
def block_flow(request: BlockRequest):
    result = block_traffic_rest(
        dpid=request.dpid,
        ip_src=request.ip_src,
        ip_dst=request.ip_dst,
        reason="Manual block via dashboard"
    )
    return result

@app.delete("/unblock/{block_id}")
def unblock_flow(block_id: int):
    """Endpoint para desbloquear tráfego"""
    conn = get_db_connection()
    row = conn.execute("SELECT dpid, ip_src, ip_dst FROM blocked_flows WHERE id = ?", (block_id,)).fetchone()
    conn.close()
    
    if not row:
        return {"status": "error", "message": "Bloqueio não encontrado"}
    
    result = unblock_traffic_rest(row["dpid"], row["ip_src"], row["ip_dst"])
    return result


@app.get("/api/blocked")
def get_blocked_flows():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT id, dpid, ip_src, ip_dst, timestamp, reason, active
        FROM blocked_flows
        WHERE active = 1
        ORDER BY timestamp DESC
    """).fetchall()
    conn.close()
    
    blocks = []
    for row in rows:
        blocks.append({
            "id": row["id"],
            "dpid": row["dpid"],
            "ip_src": row["ip_src"],
            "ip_dst": row["ip_dst"],
            "timestamp": datetime.datetime.fromtimestamp(row["timestamp"]).strftime('%Y-%m-%d %H:%M:%S'),
            "reason": row["reason"],
            "active": bool(row["active"])
        })
    
    return {"blocked": blocks, "total": len(blocks)}


@app.get("/api/traffic")
def get_traffic():
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM flows ORDER BY timestamp DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return {"labels": [], "datasets": []}

    timestamps = []
    malicious_counts = []
    benign_counts = []
    
    time_buckets = {}
    for row in rows:
        ts = datetime.datetime.fromtimestamp(row["timestamp"]).strftime('%H:%M')
        if ts not in time_buckets:
            time_buckets[ts] = {"malicious": 0, "benign": 0}
        
        if row["label"] == 0:  
            time_buckets[ts]["malicious"] += 1
        else:
            time_buckets[ts]["benign"] += 1
    
    timestamps = sorted(time_buckets.keys())
    malicious_counts = [time_buckets[t]["malicious"] for t in timestamps]
    benign_counts = [time_buckets[t]["benign"] for t in timestamps]

    return {
        "labels": timestamps,
        "datasets": [
            {
                "label": "Tráfego Malicioso",
                "data": malicious_counts,
                "borderColor": "#e53935",
                "backgroundColor": "rgba(229, 57, 53, 0.1)",
                "fill": True,
                "tension": 0.4
            },
            {
                "label": "Tráfego Benigno",
                "data": benign_counts,
                "borderColor": "#4caf50",
                "backgroundColor": "rgba(76, 175, 80, 0.1)",
                "fill": True,
                "tension": 0.4
            }
        ]
    }

@app.get("/api/overview")
def get_network_overview():
    try:
        switches_resp = requests.get("{}/stats/switches".format(RYU_REST_URL))
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

    total = len(rows)
    suspicious = sum(1 for row in rows if row["label"] == 0) if rows else 1
    legitimate = total - suspicious
    legitimate_pct = round((legitimate / total) * 100, 1) if total > 0 else 100.0
    attacks_detected = suspicious
    active_rules = conn.execute("SELECT COUNT(*) FROM blocked_flows WHERE active = 1").fetchone()
    rules_active = active_rules[0] if active_rules else 0
    conn.close()
    return {
        "attacks_detected": attacks_detected,
        "suspicious_traffic": suspicious,
        "legitimate_traffic_pct": legitimate_pct,
        "rules_active": rules_active
    }


@app.get("/api/alerts")
def get_recent_alerts(limit: int = 5):
    conn = get_db_connection()
    rows = conn.execute("SELECT ip_src, ip_dst, timestamp FROM flows WHERE label = 0 ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()

    alerts = [{"source": r["ip_src"], "destination": r["ip_dst"], "time": r["timestamp"]} for r in rows]
    return {"alerts": alerts}


@app.get("/api/contacts")
def list_contacts():
    conn = get_db_connection()
    rows = conn.execute("SELECT id, name, email, enabled FROM alert_contacts ORDER BY id DESC").fetchall()
    conn.close()
    return {"contacts": [{"id": r["id"], "name": r["name"], "email": r["email"], "enabled": bool(r["enabled"])} for r in rows]}

@app.post("/api/contacts")
def create_contact(contact: ContactRequest):
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO alert_contacts(name, email, enabled) VALUES (?, ?, ?)", (contact.name, contact.email, int(contact.enabled)))
        conn.commit()
        return {"status": "success"}
    except sqlite3.IntegrityError:
        return {"status": "error", "message": "E-mail já cadastrado"}
    finally:
        conn.close()

@app.put("/api/contacts/{contact_id}")
def update_contact(contact_id: int, contact: ContactUpdateRequest):
    conn = get_db_connection()
    
    current = conn.execute(
        "SELECT name, email, enabled FROM alert_contacts WHERE id = ?", 
        (contact_id,)
    ).fetchone()
    
    if not current:
        conn.close()
        return {"status": "error", "message": "Contato não encontrado"}
    
    name = contact.name if contact.name is not None else current["name"]
    email = contact.email if contact.email is not None else current["email"]
    enabled = contact.enabled if contact.enabled is not None else bool(current["enabled"])
    
    try:
        conn.execute(
            "UPDATE alert_contacts SET name = ?, email = ?, enabled = ? WHERE id = ?",
            (name, email, int(enabled), contact_id)
        )
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Contato atualizado"}
    except sqlite3.IntegrityError:
        conn.close()
        return {"status": "error", "message": "E-mail já cadastrado"}
    except Exception as e:
        conn.close()
        return {"status": "error", "message": str(e)}

@app.delete("/api/contacts/{contact_id}")
def delete_contact(contact_id: int):
    conn = get_db_connection()
    conn.execute("DELETE FROM alert_contacts WHERE id = ?", (contact_id,))
    conn.commit()
    conn.close()
    return {"status": "success"}
