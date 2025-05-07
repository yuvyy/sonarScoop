import requests
import pandas as pd
import json
import os
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# === CONFIGURATION ===
SONAR_URL = "http://localhost:9000"
LOGIN_URL = f"{SONAR_URL}/api/authentication/login"
CREDENTIALS_FILE = "credentials.json"
EXPORT_DIR = "exports"  # Directory where Excel files will be saved


def info(msg): print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")
def success(msg): print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {msg}")
def warning(msg): print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")
def error(msg): print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")
def prompt(msg): return input(f"{Fore.BLUE}[INPUT]{Style.RESET_ALL} {msg} ").strip()

def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        return json.load(open(CREDENTIALS_FILE, 'r'))
    return None

def save_credentials(username, password):
    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump({"username": username, "password": password}, f)
    success("Credentials saved for future use.")

def login_and_get_jwt():
    session = requests.Session()
    creds = load_credentials()

    if creds:
        use_saved = prompt("Use saved credentials? (y/n):").lower() == 'y'
        if use_saved:
            username, password = creds["username"], creds["password"]
        else:
            username = prompt("Enter username:")
            password = prompt("Enter password:")
    else:
        username = prompt("Enter username:")
        password = prompt("Enter password:")

    info("Logging in...")
    login_data = {'login': username, 'password': password}
    response = session.post(LOGIN_URL, data=login_data)

    if response.status_code != 200 or 'JWT-SESSION' not in session.cookies:
        error("Login failed or JWT token not found.")
        raise Exception("Login failed.")

    jwt_token = session.cookies.get('JWT-SESSION')
    success("Logged in successfully. JWT Token retrieved.")

    if not creds:
        save = prompt("Save credentials for future use? (y/n):").lower() == 'y'
        if save:
            save_credentials(username, password)

    return session, jwt_token

def fetch_project_keys(session):
    info("Fetching project keys from SonarQube...")
    project_keys = []
    page = 1

    while True:
        params = {'p': page, 'ps': 100}
        response = session.get(f"{SONAR_URL}/api/projects/search", params=params)
        response.raise_for_status()
        data = response.json()

        for project in data.get("components", []):
            project_keys.append({"name": project.get("name"), "key": project.get("key")})

        if page * 100 >= data["paging"]["total"]:
            break
        page += 1

    success(f"Found {len(project_keys)} projects.")
    return project_keys

def choose_project_key(session):
    projects = fetch_project_keys(session)
    if not projects:
        error("No projects found.")
        raise Exception("No projects available.")

    print("\nAvailable Projects:")
    for i, proj in enumerate(projects, 1):
        print(f"  {Fore.YELLOW}{i}. {proj['name']} ({proj['key']}){Style.RESET_ALL}")

    while True:
        choice = prompt("Select a project by number:")
        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(projects):
                return projects[index - 1]['key']
        warning("Invalid selection. Please try again.")

def fetch_security_hotspots(session, projectKey):
    info(f"Fetching security hotspots for project '{projectKey}'...")
    url = f"{SONAR_URL}/api/hotspots/search"
    page = 1
    hotspots = []

    while True:
        params = {"projectKey": projectKey, "ps": 500, "p": page}
        response = session.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        for h in data["hotspots"]:
            hotspots.append({
                "Vulnerability Name": h.get("message"),
                "File": h.get("component"),
                "Line": h.get("line")
            })

        if page * 500 >= data["paging"]["total"]:
            break
        page += 1

    success(f"Retrieved {len(hotspots)} security hotspots.")
    return hotspots

def export_to_excel(hotspots, filename):
    os.makedirs(EXPORT_DIR, exist_ok=True)
    filepath = os.path.join(EXPORT_DIR, filename)
    df = pd.DataFrame(hotspots)
    df.to_excel(filename, index=False)
    success(f"Exported {len(hotspots)} hotspots to '{filepath}'.")

def logout(session):
    info("Logging out...")
    logout_url = f"{SONAR_URL}/sessions/logout"
    response = session.get(logout_url)
    if response.status_code == 200:
        success("Logged out successfully.")
    else:
        warning(f"Logout failed with status code {response.status_code}.")
    session.close()

if __name__ == "__main__":
    session, jwt = login_and_get_jwt()
    try:
        while True:
            print("\n" + "=" * 50)
            projectKey = choose_project_key(session)
            hotspots = fetch_security_hotspots(session, projectKey)
            export_to_excel(hotspots, f"{projectKey}.xlsx")

            cont = prompt("Do you want to export another project? (y/n):").lower()
            if cont != 'y':
                break
    finally:
        logout(session)