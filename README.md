# gRPC Client
A Postman-style gRPC client built with PyQt5 — send gRPC requests, explore services, test  methods  in an easy-to-use GUI.
This tool helps developers test, debug, and interact with gRPC services easily, without needing to write boilerplate code.
Cross-platform PyQt5 Postman-style gRPC desktop client to test and debug microservices.


gRPC GUI Client / gRPC Testing Desktop tool

---

## ✨ Features

- **Multiple Tabs**
  - Open and manage multiple gRPC connections at the same time.
  - Rename and save tabs with SQLite database support.

- **Connection Management**
  - Supports **insecure** and **secure** (TLS/SSL) connections.
  - Add and configure certificates per tab.
  - Save and delete certificates.

- **Service Import**
  - Load services using:
    - **gRPC Reflection**
    - **Proto File Compilation**
  - Add additional proto import paths.

- **Request/Response Handling**
  - Auto-populate request messages from `.proto` definitions.
  - Send and view structured gRPC responses.

- **Metadata Support**
  - Add custom metadata to requests.
  - Save metadata for each tab to database.

- **Authorization**
  - Supports multiple authentication mechanisms:
    - API Key
    - Bearer Token
    - Basic Auth
    - OAuth2

- **Persistence**
  - Tabs, certificates, metadata, and authorization info are saved in SQLite DB.

---

## 🖥️ Screenshot


<img width="1914" height="1053" alt="image" src="https://github.com/user-attachments/assets/8ad79da7-3683-46c7-b596-2dc629fc1715" />

---

## 🚀 Getting Started

### Prerequisites
- Tested on Python 3.13.5
- `pip` or `conda`
- gRPC tools (`grpcio`, `grpcio-tools`)

### Installation
```bash
# Clone the repository
git clone https://github.com/pawanbattu/gRPC_Client.git
cd gRPC_Client

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt

cd src 
python main.py
