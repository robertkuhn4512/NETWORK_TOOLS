#!/bin/bash
rsync -av --exclude '.git' --exclude 'container_data' -e "ssh -i ~/.ssh/developer_network_tools_id_ed25519" /Users/rob/Desktop/network_tools/NETWORK_TOOLS developer_network_tools@network_tools.local:
