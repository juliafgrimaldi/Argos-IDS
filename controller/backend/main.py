from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import pandas as pd
import os

app = FastAPI()

CSV_FILE = 'traffic_predict.csv'


app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html", "r") as f:
        return f.read()

@app.get("/api/traffic")
def get_traffic():
    if not os.path.exists(CSV_FILE):
        return {"error": "Arquivo CSV não encontrado."}

    df = pd.read_csv(CSV_FILE)

    # Agrega bytes totais por switch (dpid)
    traffic = df.groupby('dpid')['bytes'].sum().reset_index()
    # Converte para lista de dicts para JSON
    data = traffic.to_dict(orient='records')
    return {"traffic": data}

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
