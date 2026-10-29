from sqlalchemy import Column, Integer, String, Float, Text, Date, ForeignKey
from sqlalchemy.orm import relationship
from app.db.base import Base

class CVE(Base):
    __tablename__ = 'cves'
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=False)
    published_date = Column(Date, nullable=False)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String(20), nullable=True)
    cwe_id = Column(Integer, ForeignKey('cwes.id'))
    cwe = relationship('CWE', back_populates='cves')
    exploit_type = Column(String(100), nullable=True)
