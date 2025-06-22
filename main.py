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
    name = Column(String, unique=True, index=True)
    price = Column(Float)
    description = Column(String, nullable=True)


Base.metadata.create_all(bind=engine)

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class DepositWithdrawRequest(BaseModel):
    amount: float

class TransferRequest(BaseModel):
    recipient_username: str
    amount: float

class ProductRequest(BaseModel):
    name: str
    price: float
    description: str = None

class BuyRequest(BaseModel):
    product_id: int


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(credentials: HTTPBasicCredentials = Depends(security), db=Depends(get_db)):
    """Authenticates the user based on Basic Auth credentials."""
    username = credentials.username
    password = credentials.password

    user = db.query(User).filter(User.username == username).first()
    if not user or not bcrypt.verify(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


EXCHANGE_RATE_API_URL = os.getenv("EXCHANGE_RATE_API_URL", "https://v6.exchangerate-api.com/v6")
EXCHANGE_RATE_API_KEY = os.getenv("EXCHANGE_RATE_API_KEY", "ed65b227c4b9d0cb1b3e8649") 

def get_inr_to_usd_rate():
    """Fetches the current INR to USD exchange rate."""
    if not EXCHANGE_RATE_API_KEY or EXCHANGE_RATE_API_KEY == "YOUR_API_KEY_HERE":
        print("WARNING: Exchange rate API key is not set or is default. USD conversion will fail.")
        return None

    try:
       
        url = f"{EXCHANGE_RATE_API_URL}/{EXCHANGE_RATE_API_KEY}/latest/INR"
        response = requests.get(url, timeout=5) 
        response.raise_for_status() 
        data = response.json()

       
        usd_rate = data.get('conversion_rates', {}).get('USD')
        
        if usd_rate is None:
            print(f"Error: USD rate not found in API response: {data}")
            return None
            
        return usd_rate
    except requests.exceptions.RequestException as e:
        print(f"Error fetching exchange rate: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during rate fetching: {e}")
        return None




@app.post("/signup", status_code=201)
def signup(user_data: UserCreate, db=Depends(get_db)):
    """Registers a new user."""
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")

    hashed_password = bcrypt.hash(user_data.password)
    new_user = User(username=user_data.username, password_hash=hashed_password, balance=0.0)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully", "user_id": new_user.id}

@app.post("/login")
def login(credentials: HTTPBasicCredentials = Depends(security)):
    """Logs in a user and returns a success message."""
    
    return {"message": "Login successful"}

@app.get("/balance")
def get_balance(currency: str = Query("INR"), user: User = Depends(get_current_user)):
    """Retrieves the authenticated user's balance, with optional currency conversion."""
    current_balance_inr = user.balance 

    if currency.upper() == "USD":
        usd_rate = get_inr_to_usd_rate()
        if usd_rate is not None:
            converted_balance_usd = current_balance_inr * usd_rate
            return {"balance": converted_balance_usd, "currency": "USD"}
        else:
            raise HTTPException(status_code=503, detail="Service unavailable: Could not fetch USD exchange rate.")
    elif currency.upper() == "INR":
        return {"balance": current_balance_inr, "currency": "INR"}
    else:
        raise HTTPException(status_code=400, detail="Unsupported currency. Only INR and USD are supported.")

@app.post("/deposit")
def deposit(data: DepositWithdrawRequest, user: User = Depends(get_current_user), db=Depends(get_db)):
    """Deposits funds into the user's account."""
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    user.balance += data.amount
    transaction = Transaction(
        user_id=user.id,
        kind="deposit",
        amt=data.amount,
        updated_bal=user.balance
    )
    db.add(transaction)
    db.commit()
    db.refresh(user)
    return {"message": f"Deposited {data.amount} INR. New balance: {user.balance} INR"}

@app.post("/withdraw")
def withdraw(data: DepositWithdrawRequest, user: User = Depends(get_current_user), db=Depends(get_db)):
    """Withdraws funds from the user's account."""
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    if user.balance < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    user.balance -= data.amount
    transaction = Transaction(
        user_id=user.id,
        kind="withdraw",
        amt=data.amount,
        updated_bal=user.balance
    )
    db.add(transaction)
    db.commit()
    db.refresh(user)
    return {"message": f"Withdrew {data.amount} INR. New balance: {user.balance} INR"}

@app.post("/transfer")
def transfer(data: TransferRequest, sender: User = Depends(get_current_user), db=Depends(get_db)):
    """Transfers funds to another user."""
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    if sender.balance < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    if sender.username == data.recipient_username:
        raise HTTPException(status_code=400, detail="Cannot transfer to yourself")

    recipient = db.query(User).filter(User.username == data.recipient_username).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient user not found")

    sender.balance -= data.amount
    recipient.balance += data.amount

    sender_txn = Transaction(
        user_id=sender.id,
        kind="transfer_sent",
        amt=data.amount,
        updated_bal=sender.balance
    )
    recipient_txn = Transaction(
        user_id=recipient.id,
        kind="transfer_received",
        amt=data.amount,
        updated_bal=recipient.balance
    )

    db.add_all([sender_txn, recipient_txn])
    db.commit()
    db.refresh(sender)
    db.refresh(recipient)
    return {"message": f"Transferred {data.amount} INR to {data.recipient_username}. Your new balance: {sender.balance} INR"}

@app.get("/stmt")
def statement(user: User = Depends(get_current_user), db=Depends(get_db)):
    """Retrieves the transaction statement for the authenticated user."""
    txns = db.query(Transaction).filter(Transaction.user_id == user.id).order_by(Transaction.timestamp.desc()).all()
    return [
        {"kind": txn.kind, "amt": txn.amt, "updated_bal": txn.updated_bal, "timestamp": txn.timestamp.isoformat()} for txn in txns
    ]

@app.post("/product", status_code=201)
def add_product(data: ProductRequest, user: User = Depends(get_current_user), db=Depends(get_db)):
    """Adds a new product (admin/internal use, assuming user has permissions)."""
   
    product = Product(name=data.name, price=data.price, description=data.description)
    db.add(product)
    db.commit()
    db.refresh(product)
    return {"id": product.id, "message": "Product added"}

@app.get("/product")
def list_products(db=Depends(get_db)):
    """Lists all available products."""
    products = db.query(Product).all()
    return [
        {"id": p.id, "name": p.name, "price": p.price, "description": p.description} for p in products
    ]

@app.post("/buy")
def buy_product(data: BuyRequest, user: User = Depends(get_current_user), db=Depends(get_db)):
    """Allows a user to buy a product."""
    product = db.query(Product).filter(Product.id == data.product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    if user.balance < product.price:
        raise HTTPException(status_code=400, detail="Insufficient balance to buy this product")

    user.balance -= product.price
    transaction = Transaction(
        user_id=user.id,
        kind="product_purchase",
        amt=product.price,
        updated_bal=user.balance
    )
    db.add(transaction)
    db.commit()
    db.refresh(user)
    return {"message": f"Successfully purchased {product.name} for {product.price} INR. New balance: {user.balance} INR"}