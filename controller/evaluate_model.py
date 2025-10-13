import requests

flow_rule = {
    "dpid": 1,
    "priority": 65535,  # Prioridade máxima
    "match": {
        "ipv4_src": "10.0.0.1",
        "ipv4_dst": "10.0.0.2",
        "eth_type": 2048
    },
    "actions": []  # DROP
}

response = requests.post("http://127.0.0.1:8080/stats/flowentry/add", json=flow_rule)
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

# Verificar flows
import time
time.sleep(1)
flows = requests.get("http://127.0.0.1:8080/stats/flow/1").json()

for flow in flows.get('1', []):
    if flow.get('priority') == 65535:
        print("\n✅ Flow de bloqueio encontrado:")
        print(f"   Priority: {flow['priority']}")
        print(f"   Match: {flow['match']}")
        print(f"   Actions: {flow['actions']}")