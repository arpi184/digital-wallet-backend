from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from passlib.hash import bcrypt
from datetime import datetime
import requests
import base64
import os

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = "sqlite:///./wallet.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

security = HTTPBasic()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    balance = Column(Float, default=0.0)
    transactions = relationship("Transaction", back_populates="user")

class Transaction(Base):
    __tablename__ = 'transactions'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    kind = Column(String)
    amt = Column(Float)
    updated_bal = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="transactions")

class Product(Base):
    __tablename__ = 'products'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    price = Column(Float)
    description = Column(String)

Base.metadata.create_all(bind=engine)

class RegisterRequest(BaseModel):
    username: str
    password: str

class FundRequest(BaseModel):
    amt: float

class PayRequest(BaseModel):
    to: str
    amt: float

class ProductRequest(BaseModel):
    name: str
    price: float
    description: str

class BuyRequest(BaseModel):
    product_id: int


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(credentials: HTTPBasicCredentials = Depends(security), db=Depends(get_db)):
    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not bcrypt.verify(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return user

@app.post("/register", status_code=201)
def register(data: RegisterRequest, db=Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="User already exists")
    user = User(username=data.username, password_hash=bcrypt.hash(data.password))
    db.add(user)
    db.commit()
    return {"message": "User registered"}

@app.post("/fund")
def fund(data: FundRequest, user: User = Depends(get_current_user), db=Depends(get_db)):
    user.balance += data.amt
    txn = Transaction(user_id=user.id, kind="credit", amt=data.amt, updated_bal=user.balance)
    db.add(txn)
    db.commit()
    return {"balance": user.balance}

@app.post("/pay")
def pay(data: PayRequest, user: User = Depends(get_current_user), db=Depends(get_db)):
    if user.balance < data.amt:
        raise HTTPException(status_code=400, detail="Insufficient funds")
    recipient = db.query(User).filter(User.username == data.to).first()
    if not recipient:
        raise HTTPException(status_code=400, detail="Recipient does not exist")
    user.balance -= data.amt
    recipient.balance += data.amt
    db.add(Transaction(user_id=user.id, kind="debit", amt=data.amt, updated_bal=user.balance))
    db.add(Transaction(user_id=recipient.id, kind="credit", amt=data.amt, updated_bal=recipient.balance))
    db.commit()
    return {"balance": user.balance}

@app.get("/bal")
def get_balance(currency: str = Query(default="INR"), user: User = Depends(get_current_user), db=Depends(get_db)):
    if currency.upper() == "INR":
        return {"balance": user.balance, "currency": "INR"}
    api_key = os.getenv("CURRENCY_API_KEY")
    url = f"https://api.currencyapi.com/v3/latest?apikey={api_key}&base_currency=INR"
    resp = requests.get(url).json()
    if currency.upper() not in resp['data']:
        raise HTTPException(status_code=400, detail="Invalid currency")
    rate = resp['data'][currency.upper()]['value']
    return {"balance": round(user.balance * rate, 2), "currency": currency.upper()}

@app.get("/stmt")
def statement(user: User = Depends(get_current_user), db=Depends(get_db)):
    txns = db.query(Transaction).filter(Transaction.user_id == user.id).order_by(Transaction.timestamp.desc()).all()
    return [
        {"kind": txn.kind, "amt": txn.amt, "updated_bal": txn.updated_bal, "timestamp": txn.timestamp.isoformat()} for txn in txns
    ]

@app.post("/product", status_code=201)
def add_product(data: ProductRequest, user: User = Depends(get_current_user), db=Depends(get_db)):
    product = Product(name=data.name, price=data.price, description=data.description)
    db.add(product)
    db.commit()
    return {"id": product.id, "message": "Product added"}

@app.get("/product")
def list_products(db=Depends(get_db)):
    products = db.query(Product).all()
    return [
        {"id": p.id, "name": p.name, "price": p.price, "description": p.description} for p in products
    ]

@app.post("/buy")
def buy_product(data: BuyRequest, user: User = Depends(get_current_user), db=Depends(get_db)):
    product = db.query(Product).filter(Product.id == data.product_id).first()
    if not product or user.balance < product.price:
        raise HTTPException(status_code=400, detail="Insufficient balance or invalid product")
    user.balance -= product.price
    txn = Transaction(user_id=user.id, kind="debit", amt=product.price, updated_bal=user.balance)
    db.add(txn)
    db.commit()
    return {"message": "Product purchased", "balance": user.balance}
