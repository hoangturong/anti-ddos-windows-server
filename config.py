## Config file

max_speed_user = 500  # 1000mb/s

max_speed_server = 500   # 100000mb/s

max_conn = 30000  # 30000 connection

max_data_user = 0  # 50mb        # use 0 for disable

reset_send_data_user = 1  # 1 minutes

type_block_send_data = 2

block_time = 30  # 30 minutes

timeout_conn = 180  # 180 seconds

type_block_spam = 2

host_fw="0.0.0.0"

#host_server="127.0.0.1"

time_connect=0  # 0 second (recommend is 0)

block_on_count=15  # 15 times

reset_on_time=60  # 60 seconds

force_firewall_count=0 # (recommend is 0)

# Default IP Blocked
ban_ip=""

# 1 for Enable get all IP Sock for block, 0 for Disable
is_get_sock=1

headers = {
    "User -Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
}
# Custom sock4/5/http link for block
ban_sock = [
	"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
	
]