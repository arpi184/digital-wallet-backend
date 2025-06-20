# 💸 Digital Wallet Backend

A secure and fully functional digital wallet system built with **FastAPI**, allowing users to register, deposit funds, pay other users, view transactions, check balances in different currencies, and purchase products.

---

## 🚀 Features

✅ User registration with hashed passwords  
✅ Basic Authentication for protected endpoints  
✅ Fund wallet with INR  
✅ Transfer money to other users  
✅ View wallet balance (with optional currency conversion)  
✅ Add/view products  
✅ Purchase products using wallet  
✅ Transaction history  
✅ External API integration (currency conversion via CurrencyAPI)  
✅ Proper error handling and status codes  

---

## 🔧 Tech Stack

- **FastAPI**
- **SQLite + SQLAlchemy**
- **bcrypt** (password hashing)
- **requests** (external API)
- **dotenv** (for secret keys)
- **Uvicorn** (ASGI server)

---

## 📦 Setup Instructions

### 1. Clone the repo

```bash
git clone https://github.com/arpi184/digital-wallet-backend.git
cd digital-wallet-backend
