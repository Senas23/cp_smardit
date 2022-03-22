import logging
import os

if not os.path.exists(f"{os.getcwd()}/logs"):
    os.mkdir(f"{os.getcwd()}/logs")

logging.basicConfig(level=logging.DEBUG, filename='./logs/export_cp_to_ansible.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
log = logging.getLogger(__name__)
log.addHandler(console)
log.info('Logger created')