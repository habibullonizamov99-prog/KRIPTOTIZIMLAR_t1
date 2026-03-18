import ssl
import os
from fastapi import FastAPI, HTTPException
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI()

# 7-vazifa: Argon2id parametrlarini sozlash
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=4)

# Parolni Argon2id bilan xeshlash (Kamida 12 belgi)
hashed_pw = ph.hash("Nizomov_Habibullo_2026!")

users_db = {
    "admin_user": {"hash": hashed_pw, "role": "admin"},
    "user1": {"hash": ph.hash("User@Password123"), "role": "user"}
}

@app.get("/")
def home():
    return {"message": "HTTPS va TLS muvaffaqiyatli ishlamoqda!"}

@app.get("/admin")
def admin_page(user: str):
    # 6-vazifa: Rolni tekshirish
    if user in users_db and users_db[user]["role"] == "admin":
        return {"data": "Maxfiy admin ma'lumotlari"}
    raise HTTPException(status_code=403, detail="Sizda ruxsat yo'q!")

@app.get("/encrypt")
def encrypt_data(text: str):
    # 8-vazifa: AES-256-GCM shifrlash
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) 
    ciphertext = aesgcm.encrypt(nonce, text.encode(), None)
    return {
        "original": text,
        "shifrlangan_hex": ciphertext.hex(),
        "nonce_hex": nonce.hex()
    }

if __name__ == "__main__":
    import uvicorn
    # 5-vazifa: HTTPS serverni ishga tushirish (port 443 yoki 8000)
    uvicorn.run(app, host="0.0.0.0", port=8000, ssl_keyfile="server.key", ssl_certfile="server.crt")