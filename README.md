# 🔐 Kerberos Practical Implementation

This project provides a simplified simulation of the **Kerberos authentication protocol**, written in Java and managed with Bash scripts. It’s intended for educational use and security protocol experimentation.

---

## 📦 Project Structure

- `generate_keys.sh` – Generates 3 keys and stores them in a `.env` file:
    - `K_V` – Client–TGS key
    - `K_TGS` – TGS–AS key
    - `SK` – Secret key derived from a user-provided password
- `start.sh` – Compiles and runs the Java-based system
- `verify.sh` – Checks the validity of the generated keys
- `.env` – Environment file containing the keys (auto-generated)

---

## ⚙️ Requirements

- [Docker](https://www.docker.com/)
- Bash shell (Linux/macOS or Git Bash on Windows)
- Java JDK 11 or later

---

## 🚀 How to Run

From the root of the project folder, run the following commands:

```bash
# 1. Make the key generation script executable
chmod +x generate_keys.sh

# 2. Make the startup script executable
chmod +x start.sh

# 3. Make the verification script executable
chmod +x verify.sh

# 4. Generate keys by passing your password as an argument
./generate_keys.sh <your_password>

# 5. Start the application
./start.sh

# Once finished using the application, you can verify the content 
# written in the file with ./verify.sh

# 6. Verify the output
./verify.sh
```
