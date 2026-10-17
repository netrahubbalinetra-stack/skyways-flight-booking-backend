import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from google import genai
from bson import ObjectId
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from pymongo import MongoClient
from pydantic import field_validator

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
FRONTEND_URL = os.getenv(
    "FRONTEND_URL", "http://localhost:5173"
)

if not MONGO_URI or not JWT_SECRET_KEY:
    raise RuntimeError(
        "Please configure MONGO_URI and JWT_SECRET_KEY in backend/.env"
    )

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client["flight_booking_app"]
users = db["users"]
bookings = db["bookings"]

users.create_index("email", unique=True)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="SkyWays Flight Booking API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL,
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sample flights for development.
# Replace these with live inventory from an authorized flight API.
FLIGHTS = [
    {
        "id": "FL101",
        "flight_no": "SW 101",
        "airline": "SkyWays Demo Air",
        "from": "Belagavi",
        "to": "Bengaluru",
        "depart": "08:10",
        "arrive": "09:25",
        "duration": "1h 15m",
        "price": 2499,
        "seats": 18,
    },
    {
        "id": "FL102",
        "flight_no": "SW 102",
        "airline": "SkyWays Demo Air",
        "from": "Bengaluru",
        "to": "Mumbai",
        "depart": "10:30",
        "arrive": "12:05",
        "duration": "1h 35m",
        "price": 3999,
        "seats": 12,
    },
    {
        "id": "FL103",
        "flight_no": "SW 103",
        "airline": "SkyWays Demo Air",
        "from": "Delhi",
        "to": "Bengaluru",
        "depart": "14:20",
        "arrive": "17:05",
        "duration": "2h 45m",
        "price": 5299,
        "seats": 20,
    },
    {
        "id": "FL104",
        "flight_no": "SW 104",
        "airline": "SkyWays Demo Air",
        "from": "Mumbai",
        "to": "Delhi",
        "depart": "18:15",
        "arrive": "20:25",
        "duration": "2h 10m",
        "price": 4599,
        "seats": 15,
    },
    {
        "id": "FL105",
        "flight_no": "SW 105",
        "airline": "SkyWays Demo Air",
        "from": "Bengaluru",
        "to": "Hyderabad",
        "depart": "07:45",
        "arrive": "08:55",
        "duration": "1h 10m",
        "price": 2899,
        "seats": 16,
    },
    {
        "id": "FL106",
        "flight_no": "SW 106",
        "airline": "SkyWays Demo Air",
        "from": "Delhi",
        "to": "Mumbai",
        "depart": "11:00",
        "arrive": "13:10",
        "duration": "2h 10m",
        "price": 4799,
        "seats": 10,
    },
]


# ---------- Request models ----------
class SignupData(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)

    @field_validator("password")
    @classmethod
    def check_password_bytes(cls, value):
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must not exceed 72 bytes")
        return value


class LoginData(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=72)

    @field_validator("password")
    @classmethod
    def check_password_bytes(cls, value):
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must not exceed 72 bytes")
        return value

class BookingData(BaseModel):
    flight_id: str
    travel_date: str
    passengers: int = Field(ge=1, le=9)
    passenger_name: str = Field(min_length=2, max_length=100)
    seat: str = Field(min_length=1, max_length=5)


class ChatData(BaseModel):
    message: str = Field(min_length=1, max_length=1000)


# ---------- Helpers ----------

def create_token(email: str) -> str:
    expires = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_MINUTES
    )
    return jwt.encode(
        {"sub": email, "exp": expires},
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


def serialize_booking(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    return doc


def get_current_user(
    authorization: Optional[str] = Header(default=None),
):
    if not authorization or not authorization.lower().startswith(
        "bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="Please log in first.",
        )

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
        email = payload.get("sub")

        if not email:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token.",
            )

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Session expired. Please log in again.",
        )

    user = users.find_one({"email": email})

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Account not found.",
        )

    return {
        "id": str(user["_id"]),
        "name": user["name"],
        "email": user["email"],
    }


# ---------- General endpoints ----------

@app.get("/")
def root():
    return {
        "message": "SkyWays Flight Booking API is running",
        "documentation": "/docs",
    }


@app.get("/health")
def health():
    try:
        client.admin.command("ping")
        return {"api": "running", "mongodb": "connected"}
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="MongoDB is not connected. Check your database.",
        )


# ---------- Signup and login ----------

@app.post("/signup", status_code=201)
def signup(data: SignupData):
    email = str(data.email).lower().strip()

    existing = users.find_one({"email": email})

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Email already registered. Please log in.",
        )

    user = {
        "name": data.name.strip(),
        "email": email,
        "password_hash": pwd_context.hash(data.password),
        "created_at": datetime.now(timezone.utc),
    }

    result = users.insert_one(user)

    return {
        "message": "Account created successfully.",
        "user_id": str(result.inserted_id),
    }


@app.post("/login")
def login(data: LoginData):
    email = str(data.email).lower().strip()
    user = users.find_one({"email": email})

    if not user or not pwd_context.verify(
        data.password, user["password_hash"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password.",
        )

    return {
        "message": "Login successful",
        "access_token": create_token(email),
        "token_type": "bearer",
        "user": {
            "name": user["name"],
            "email": user["email"],
        },
    }


@app.get("/me")
def get_profile(user=Depends(get_current_user)):
    return user


# ---------- Flight search ----------

@app.get("/flights")
@app.get("/buslist")
def get_flights(
    origin: Optional[str] = None,
    destination: Optional[str] = None,
):
    result = FLIGHTS

    if origin:
        result = [
            flight for flight in result
            if flight["from"].lower() == origin.lower()
        ]

    if destination:
        result = [
            flight for flight in result
            if flight["to"].lower() == destination.lower()
        ]

    return {
        "flights": result,
        "demo_data": True,
    }


# ---------- Create booking ----------

@app.post("/bookings", status_code=201)
def create_booking(
    data: BookingData,
    user=Depends(get_current_user),
):
    flight = next(
        (
            flight for flight in FLIGHTS
            if flight["id"] == data.flight_id
        ),
        None,
    )

    if not flight:
        raise HTTPException(
            status_code=404,
            detail="Flight not found.",
        )

    try:
        travel_date = datetime.strptime(
            data.travel_date, "%Y-%m-%d"
        ).date()
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid travel date.",
        )

    if travel_date < datetime.now().date():
        raise HTTPException(
            status_code=400,
            detail="Travel date cannot be in the past.",
        )

    # Demo seat validation only. Not a live aircraft seat map.
    if data.seat not in {
        "12A", "12B", "12C", "12D", "12E", "12F",
        "14A", "14B", "14C", "14D", "14E", "14F",
    }:
        raise HTTPException(
            status_code=400,
            detail="Please choose an available demo seat.",
        )

    total = flight["price"] * data.passengers

    booking = {
        "user_email": user["email"],
        "user_name": user["name"],
        "flight": flight,
        "travel_date": data.travel_date,
        "passengers": data.passengers,
        "passenger_name": data.passenger_name.strip(),
        "seat": data.seat,
        "total_amount": total,
        "payment_status": "DEMO_PAID",
        "booking_status": "CONFIRMED",
        "payment_note": "Demo payment. No money was charged.",
        "booking_reference": (
            "SW" + datetime.now().strftime("%y%m%d%H%M%S")
            + str(ObjectId())[-4:].upper()
        ),
        "created_at": datetime.now(timezone.utc),
    }

    result = bookings.insert_one(booking)
    booking["_id"] = result.inserted_id

    return {
        "message": "Demo booking confirmed!",
        "booking": serialize_booking(booking),
    }


# ---------- Booking history ----------

@app.get("/bookings")
def get_my_bookings(user=Depends(get_current_user)):
    records = list(
        bookings.find({"user_email": user["email"]})
        .sort("created_at", -1)
    )

    return {
        "bookings": [
            serialize_booking(record)
            for record in records
        ]
    }


# ---------- Cancel booking ----------

@app.delete("/bookings/{booking_id}")
def cancel_booking(
    booking_id: str,
    user=Depends(get_current_user),
):
    if not ObjectId.is_valid(booking_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid booking ID.",
        )

    booking = bookings.find_one({
        "_id": ObjectId(booking_id),
        "user_email": user["email"],
    })

    if not booking:
        raise HTTPException(
            status_code=404,
            detail="Booking not found.",
        )

    if booking["booking_status"] == "CANCELLED":
        return {"message": "Booking already cancelled."}

    bookings.update_one(
        {"_id": booking["_id"]},
        {"$set": {"booking_status": "CANCELLED"}},
    )

    return {
        "message": (
            "Demo booking cancelled. "
            "No real refund was processed."
        )
    }


# ---------- Built-in flight assistant ----------

@app.post("/ai/chat")
def ai_chat(
    data: ChatData,
    user=Depends(get_current_user),
):
    api_key = os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="Gemini API key is missing from backend/.env",
        )

    try:
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model=model,
            contents=data.message,
            config={
                "system_instruction": (
                    "You are SkyWays Flight Helper, an AI assistant "
                    "for a flight booking demo application. "
                    "Answer briefly and clearly. Help with flight "
                    "search, signup, login, bookings, seats, and "
                    "cancellations. Do not claim to make bookings, "
                    "cancel tickets, process refunds, or charge "
                    "payments yourself. The application uses demo "
                    "flight data and simulated payments. Explain "
                    "when information is unavailable."
                ),
                "max_output_tokens": 300,
            },
        )

        answer = response.text

        if not answer:
            answer = "Sorry, I couldn't generate a response. Please try again."

        return {
            "answer": answer,
            "assistant": "SkyWays AI",
            "model": model,
        }

    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Gemini AI is temporarily unavailable. Check your API key, model access, and internet connection.",
        )
