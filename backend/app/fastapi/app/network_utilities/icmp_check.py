"""
Check to see if a host is alive via an ICMP request.
"""
import subprocess
import platform
import asyncio
import os
async def pingOk(sHost):
    try:
        # Unblock when swapping to the container in the future.
        # Both are enabled on the container but only ping works on my laptop for now
        response = os.system("fping -c2 -t500 " + sHost)
        # response = os.system("ping -c1 " + sHost)
        if response == 0:
            print(f'Host {sHost} is pingable')
            return True
        else:
            print(f'Host {sHost} is not pingable')
            return False
    except:
        return False

if __name__ == '__main__':
    asyncio.run(pingOk('10.0.0.101'))