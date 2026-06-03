"""SQLAlchemy models — clean."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, LargeBinary, String
from sqlalchemy.orm import declarative_base


Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(LargeBinary, nullable=False)
    role = Column(String(32), nullable=False, default="fleet-operator")
    created_at = Column(DateTime, default=datetime.utcnow)


class Vehicle(Base):
    __tablename__ = "vehicles"
    id = Column(String(17), primary_key=True)       # VIN
    model = Column(String(64))
    owner_id = Column(String(36), index=True)
    last_seen = Column(DateTime)


class Telemetry(Base):
    __tablename__ = "telemetry"
    id = Column(Integer, primary_key=True)
    vin = Column(String(17), index=True)
    metric = Column(String(64))
    value = Column(Float)
    ts = Column(DateTime, index=True)
