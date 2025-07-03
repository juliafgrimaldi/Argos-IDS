from sqlalchemy import create_engine, Column, Integer, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

Base = declarative_base()

class TrafficStats(Base):
    __tablename__ = 'traffic_stats'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    dpid = Column(Integer)
    port_no = Column(Integer)
    rx_bytes = Column(Integer)
    tx_bytes = Column(Integer)
    rx_bps = Column(Float)
    tx_bps = Column(Float)

# Cria engine e sessão
engine = create_engine('sqlite:///traffic.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
