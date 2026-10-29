from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from app.db.base import Base

class CWE(Base):
    __tablename__ = 'cwes'
    id = Column(Integer, primary_key=True, index=True)
    cwe_code = Column(String(50), unique=True, index=True)
    name = Column(String(255))
    cves = relationship('CVE', back_populates='cwe')
