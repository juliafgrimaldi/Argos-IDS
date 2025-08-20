# Argos-IDS

## Running
1- run ry controller:
ryu-manager ryu.app.simple_switch_13 ryu.app.ofctl_rest

2- run argos-ids:
ryu-manager --wsapi-port 9000 ryu.app_ofctl_rest controller.py 

3-create topology:
python topo.py

