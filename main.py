import os
import json
import hashlib
import hmac
from urllib.parse import parse_qsl
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from jose import jwt, JWTError

from sqlalchemy import (
    create_engine, String, Integer, DateTime, Float, ForeignKey,
    UniqueConstraint, select
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session


# ----------------- Config -----------------
DATABASE_URL = os.getenv("DATABASE_URL")
BOT_TOKEN = os.getenv("BOT_TOKEN")
JWT_SECRET = os.getenv("JWT_SECRET", "change_me")
JWT_ALG = "HS256"
JWT_TTL_DAYS = 30

WEBAPP_ORIGIN = os.getenv("WEBAPP_ORIGIN", "https://ayanssss.github.io")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is required")


# ----------------- DB -----------------
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    telegram_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Order(Base):
    __tablename__ = "orders"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    description: Mapped[str] = mapped_column(String(2000))
    address_text: Mapped[str] = mapped_column(String(500))
    lat: Mapped[float] = mapped_column(Float)
    lon: Mapped[float] = mapped_column(Float)

    status: Mapped[str] = mapped_column(String(32), default="open", index=True)  # open/in_progress/canceled
    accepted_master_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class OrderResponse(Base):
    __tablename__ = "order_responses"
    __table_args__ = (UniqueConstraint("order_id", "master_id", name="uq_order_master"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id"), index=True)
    master_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending/accepted/rejected/withdrawn
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)


# ----------------- Telegram initData verify -----------------
def verify_init_data(init_data: str, bot_token: str) -> dict:
    data = dict(parse_qsl(init_data, keep_blank_values=True))
    if "hash" not in data:
        raise ValueError("No hash in initData")

    received_hash = data.pop("hash")
    pairs = [f"{k}={v}" for k, v in sorted(data.items())]
    data_check_string = "\n".join(pairs).encode()

    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    calculated_hash = hmac.new(secret_key, data_check_string, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        raise ValueError("Invalid initData hash")

    return data


# ----------------- Auth helpers -----------------
def create_token(user_id: int) -> str:
    exp = datetime.utcnow() + timedelta(days=JWT_TTL_DAYS)
    return jwt.encode({"sub": str(user_id), "exp": exp}, JWT_SECRET, algorithm=JWT_ALG)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ----------------- Schemas -----------------
class AuthIn(BaseModel):
    initData: str

class AuthOut(BaseModel):
    token: str

class MeOut(BaseModel):
    id: int
    telegram_id: int
    name: Optional[str]
    username: Optional[str]

class OrderCreateIn(BaseModel):
    description: str = Field(min_length=1, max_length=2000)
    address_text: str = Field(min_length=1, max_length=500)
    lat: float
    lon: float

class OrderOut(BaseModel):
    id: int
    client_id: int
    description: str
    address_text: str
    lat: float
    lon: float
    status: str
    accepted_master_id: Optional[int]
    created_at: datetime

class ResponseOut(BaseModel):
    id: int
    order_id: int
    master_id: int
    status: str
    created_at: datetime

class OrderDetailsOut(BaseModel):
    order: OrderOut
    responses: List[ResponseOut]

class AcceptIn(BaseModel):
    response_id: int


# ----------------- App -----------------
app = FastAPI(title="TG Orders API (no city/phone)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[WEBAPP_ORIGIN, "https://ayanssss.github.io"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def _startup():
    init_db()


# ----------------- Routes -----------------
@app.post("/auth/telegram", response_model=AuthOut)
def auth_telegram(payload: AuthIn, db: Session = Depends(get_db)):
    try:
        data = verify_init_data(payload.initData, BOT_TOKEN)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    user_raw = data.get("user")
    if not user_raw:
        raise HTTPException(status_code=400, detail="No user in initData")

    try:
        tg_user = json.loads(user_raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid user JSON")

    telegram_id = int(tg_user["id"])
    name = (tg_user.get("first_name", "") + " " + tg_user.get("last_name", "")).strip() or None
    username = tg_user.get("username")

    user = db.execute(select(User).where(User.telegram_id == telegram_id)).scalar_one_or_none()
    if not user:
        user = User(telegram_id=telegram_id, name=name, username=username)
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        user.name = name
        user.username = username
        db.commit()

    return AuthOut(token=create_token(user.id))


@app.get("/me", response_model=MeOut)
def me(current: User = Depends(get_current_user)):
    return MeOut(
        id=current.id,
        telegram_id=current.telegram_id,
        name=current.name,
        username=current.username,
    )


# ---- Client: Orders ----
@app.post("/orders", response_model=OrderOut)
def create_order(body: OrderCreateIn, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    order = Order(
        client_id=current.id,
        description=body.description.strip(),
        address_text=body.address_text.strip(),
        lat=body.lat,
        lon=body.lon,
        status="open",
        accepted_master_id=None,
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    return OrderOut(**order.__dict__)

@app.get("/orders/my", response_model=List[OrderOut])
def my_orders(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    rows = db.execute(
        select(Order).where(Order.client_id == current.id).order_by(Order.created_at.desc())
    ).scalars().all()
    return [OrderOut(**o.__dict__) for o in rows]

@app.get("/orders/{order_id}", response_model=OrderDetailsOut)
def order_details(order_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    order = db.get(Order, order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    is_client = (order.client_id == current.id)
    my_resp = db.execute(
        select(OrderResponse).where(OrderResponse.order_id == order_id, OrderResponse.master_id == current.id)
    ).scalar_one_or_none()
    is_involved_master = my_resp is not None or (order.accepted_master_id == current.id)

    if not (is_client or is_involved_master):
        raise HTTPException(status_code=403, detail="Forbidden")

    responses = db.execute(
        select(OrderResponse).where(OrderResponse.order_id == order_id).order_by(OrderResponse.created_at.desc())
    ).scalars().all()

    if not is_client:
        responses = [r for r in responses if r.master_id == current.id]

    return OrderDetailsOut(
        order=OrderOut(**order.__dict__),
        responses=[ResponseOut(**r.__dict__) for r in responses],
    )

@app.post("/orders/{order_id}/cancel")
def cancel_order(order_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    order = db.get(Order, order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.client_id != current.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if order.status == "canceled":
        return {"ok": True}

    order.status = "canceled"
    db.commit()
    return {"ok": True}


# ---- Master: feed & respond ----
@app.get("/orders/feed", response_model=List[OrderOut])
def feed(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    rows = db.execute(
        select(Order).where(Order.status == "open").order_by(Order.created_at.desc())
    ).scalars().all()
    return [OrderOut(**o.__dict__) for o in rows]

@app.post("/orders/{order_id}/respond", response_model=ResponseOut)
def respond(order_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    order = db.get(Order, order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.status != "open":
        raise HTTPException(status_code=400, detail="Order is not open")
    if order.client_id == current.id:
        raise HTTPException(status_code=400, detail="You cannot respond to your own order")

    existing = db.execute(
        select(OrderResponse).where(OrderResponse.order_id == order_id, OrderResponse.master_id == current.id)
    ).scalar_one_or_none()

    if existing:
        if existing.status in ("withdrawn", "rejected"):
            existing.status = "pending"
            db.commit()
        return ResponseOut(**existing.__dict__)

    resp = OrderResponse(order_id=order_id, master_id=current.id, status="pending")
    db.add(resp)
    db.commit()
    db.refresh(resp)
    return ResponseOut(**resp.__dict__)

@app.post("/orders/{order_id}/responses/me/withdraw")
def withdraw_my_response(order_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    resp = db.execute(
        select(OrderResponse).where(OrderResponse.order_id == order_id, OrderResponse.master_id == current.id)
    ).scalar_one_or_none()
    if not resp:
        raise HTTPException(status_code=404, detail="Response not found")
    if resp.status == "accepted":
        raise HTTPException(status_code=400, detail="Cannot withdraw accepted response")
    resp.status = "withdrawn"
    db.commit()
    return {"ok": True}


# ---- Client: accept/reject ----
@app.post("/orders/{order_id}/accept")
def accept_master(order_id: int, body: AcceptIn, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    order = db.get(Order, order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.client_id != current.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if order.status != "open":
        raise HTTPException(status_code=400, detail="Order is not open")

    resp = db.get(OrderResponse, body.response_id)
    if not resp or resp.order_id != order_id:
        raise HTTPException(status_code=404, detail="Response not found")
    if resp.status != "pending":
        raise HTTPException(status_code=400, detail="Response is not pending")

    order.accepted_master_id = resp.master_id
    order.status = "in_progress"

    resp.status = "accepted"

    others = db.execute(
        select(OrderResponse).where(OrderResponse.order_id == order_id, OrderResponse.id != resp.id)
    ).scalars().all()
    for r in others:
        if r.status == "pending":
            r.status = "rejected"

    db.commit()
    return {"ok": True, "accepted_master_id": order.accepted_master_id}

@app.post("/orders/{order_id}/reject")
def reject_master(order_id: int, body: AcceptIn, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    order = db.get(Order, order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.client_id != current.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if order.status != "open":
        raise HTTPException(status_code=400, detail="Order is not open")

    resp = db.get(OrderResponse, body.response_id)
    if not resp or resp.order_id != order_id:
        raise HTTPException(status_code=404, detail="Response not found")
    if resp.status != "pending":
        raise HTTPException(status_code=400, detail="Response is not pending")

    resp.status = "rejected"
    db.commit()
    return {"ok": True}