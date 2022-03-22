from utils.logger_main import log
import requests
# Disable warning messages since our API certificate is self signed
requests.packages.urllib3.disable_warnings()


class API_client:

    api_server: str
    api_server_url: str
    user: str
    port: str
    password: str
    domain: str
    policy_layer: str

    def __init__(self, api_server: str, user: str, password: str, port: str, api_key=None, domain=None) -> None:
        self.user = user
        self.port = port
        self.password = password
        self.api_key = api_key
        self.domain = domain
        self.headers = {}
        self.api_server_url = f"https://{api_server}:{port}/web_api/"

    def login(self) -> None:
        # Create login instance

        payload = {"user": self.user,
                   "password": self.password, "read-only": True}
        if self.domain is not None:
            payload['domain'] = self.domain
        if self.api_key is not None:
            payload['api-key'] = self.api_key
            del payload['user']
            del payload['password']

        response = requests.request(
            "POST", self.api_server_url + "login", headers=self.headers, json=payload, verify=False)

        if response.status_code != 200:
            log.critical(f"Login failed:{response.text}")
            exit(1)
        else:
            sid = response.json()['sid']
            self.headers['X-chkp-sid'] = sid
            log.info(f"Login successful, SID: {sid}")
            return sid

    def logout(self) -> None:
        response = requests.request(
            "POST", self.api_server_url + "logout", headers=self.headers, json={}, verify=False)
        if response.status_code != 200:
            log.critical(f"Logout failed:{response.text}")
            exit(1)
        else:
            log.info(f"Logout successful")
            return

    def publish(self) -> None:
        # Create publish instance
        response = requests.request(
            "POST", self.api_server_url + "publish", headers=self.headers, json=self.payload, verify=False)
        log.info(f"Publish response: {response}")
        return

    def run_command(self, command: str, payload: dict) -> dict:
        # Create run command instance
        response = requests.request(
            "POST", self.api_server_url + command, headers=self.headers, json=payload, verify=False)
        #log.info(f"Run command response: {response.text}")
        return response.json()
