# NetGuard: Your Personal Network Guardian

Welcome to NetGuard, your personal network guardian! This Python script helps you monitor your local network for unauthorized activities such as network scans, MITM attacks, and DoS attacks. It sends real-time notifications to your Telegram, keeping you informed and secure.

## Features
- Detects TCP scans (including SYN and NULL scans)
- Detects ARP spoofing attacks
- Detects DNS requests to suspicious domains
- Monitors for packet floods and potential DoS attacks
- Sends real-time notifications to your Telegram chat
- Logs events for later review

## Installation
### Prerequisites
- Python 3.x
- `scapy` library
- `pyTelegramBotAPI` library

### Step-by-Step Installation
1. **Clone the repository:**
    ```sh
    git clone https://github.com/yourusername/netguard.git
    cd netguard
    ```

2. **Create and activate a virtual environment:**
    ```sh
    python3 -m venv myenv
    source myenv/bin/activate  # For Windows: myenv\Scripts\activate
    ```

3. **Install the required libraries:**
    ```sh
    pip install -r requirements.txt
    ```

4. **Configure your Telegram bot:**
    - Create a bot using BotFather on Telegram.
    - Obtain your bot's API key and chat ID.
    - Update the `api` and `chat_id` variables in the script with your details.

## Usage
To run the script, use the following command:

```sh
sudo python3 netguard.py
