# Argos-IDS

## Running
1- run ry controller:
ryu-manager custom_controller.py ryu.app.ofctl_rest ryu.app.rest_topology

2- run argos-ids:
ryu-manager ids.py ryu.app.ofctl_rest --wsapi-port 9000

3-create topology:
python topo.py

4- uvicorn main:app

