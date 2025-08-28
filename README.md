
# FastAPI IMAP Login Checker (authorized use only)

⚠️ Tool ini hanya untuk akun yang kamu miliki / berizin.
Tidak untuk mengelabui deteksi provider. Gunakan rate-limit & praktik aman.


## Cara jalanin (lokal):

```bash
1) Python 3.10+
2) pip install -r requirements.txt
3) uvicorn main:app --host 0.0.0.0 --port 8000
```
    
## API Contoh

#### Dengan proxy socket

```http
  GET /testlogin/imap?auth=tiger_dragon777@i.softbank.jp|RubberSoul88
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `auth` | `string` | **Required**. Your auth key |

#### Tanpa proxy socket

```http
  GET /testlogin/imap?auth=...|...&proxy=socks5://user:pass@host:port
```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `auth`      | `string` | **Required**. auth of item to fetch |
| `proxy`      | `string` | **Required**. proxy of item to fetch |



