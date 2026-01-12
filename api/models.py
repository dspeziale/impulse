from sqlalchemy import Column, Integer, String, Boolean, Enum, ForeignKey, DateTime, Text, LargeBinary
from sqlalchemy.orm import declarative_base, relationship
from flask_login import UserMixin
import enum
from datetime import datetime

Base = declarative_base()

class UserRole(enum.Enum):
    ADMINISTRATOR = "Administrator"
    SUPERVISOR = "Supervisor"
    OPERATOR = "Operator"
    USER = "User"

class User(UserMixin, Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False)
    cognome = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    photo_url = Column(String(255), default="https://cdn.jsdelivr.net/npm/admin-lte@3.2/dist/img/avatar5.png", nullable=True) # Fallback URL
    photo_data = Column(LargeBinary, nullable=True) # BLOB storage
    cantiere_id = Column(Integer, nullable=True)
    automezzo_id = Column(Integer, nullable=True)
    commessa_id = Column(Integer, nullable=True)
    is_active_account = Column(Boolean, default=True) # Renamed to avoid conflict with UserMixin.is_active
    force_change_password = Column(Boolean, default=True)

    def get_id(self):
        return str(self.id)
    
    @property
    def is_active(self):
        return self.is_active_account

class Log(Base):
    __tablename__ = 'logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45), nullable=True)
    
    user = relationship("User", backref="logs")

class Message(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    recipient_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    subject = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    read_at = Column(DateTime, nullable=True)
    deleted_by_sender = Column(Boolean, default=False)
    deleted_by_recipient = Column(Boolean, default=False)
    
    sender = relationship("User", foreign_keys=[sender_id], backref="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], backref="received_messages")

class Notification(Base):
    __tablename__ = 'notifications'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    title = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    category = Column(String(20), default='info') # info, success, warning, danger
    timestamp = Column(DateTime, default=datetime.utcnow)
    read_at = Column(DateTime, nullable=True)
    
    user = relationship("User", backref="notifications")

class AutomezzoType(enum.Enum):
    FURGONE = "Furgone"
    CAMION = "Camion"
    SCOOTER = "Scooter"

class Automezzo(Base):
    __tablename__ = 'automezzi'
    id = Column(Integer, primary_key=True)
    tipo = Column(Enum(AutomezzoType), nullable=False)
    targa = Column(String(50), unique=True, nullable=False)
    stato = Column(String(20), default="Operativo") # Operativo, Manutenzione, etc.
    id_traccar = Column(String(50), nullable=True)
    ultima_posizione_gps = Column(String(100), nullable=True)

class Cantiere(Base):
    __tablename__ = 'cantieri'
    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False)
    indirizzo = Column(String(200), nullable=False)
    citta = Column(String(100), nullable=False)
    coordinate_gps = Column(String(100), nullable=True) # "lat,lon"
    orario_lavoro_inizio = Column(String(10), nullable=True) # "HH:MM"
    orario_lavoro_fine = Column(String(10), nullable=True) # "HH:MM"
    qr_code_univoco = Column(String(100), unique=True, nullable=True)
    automezzo_id = Column(Integer, ForeignKey('automezzi.id'), nullable=True)
    stato = Column(String(20), default="Attivo") # Attivo, Chiuso
    
    automezzo = relationship("Automezzo", backref="cantieri")

class TimbraturaType(enum.Enum):
    ENTRATA = "Entrata"
    USCITA = "Uscita"

class Timbratura(Base):
    __tablename__ = 'timbrature'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    cantiere_id = Column(Integer, ForeignKey('cantieri.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    tipo = Column(Enum(TimbraturaType), nullable=False)
    coordinate_gps = Column(String(100), nullable=True)
    distanza_validata = Column(Boolean, default=False)
    qr_code_utilizzato = Column(String(100), nullable=True)
    note = Column(Text, nullable=True) # For any extra info or manual confirm notes

    user = relationship("User", backref="timbrature")
    cantiere = relationship("Cantiere", backref="timbrature")

class AssenzaType(enum.Enum):
    MALATTIA = "Malattia"
    FERIE = "Ferie"
    PERMESSO = "Permesso"

class Assenza(Base):
    __tablename__ = 'assenze'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    tipo = Column(Enum(AssenzaType), nullable=False)
    data_inizio = Column(DateTime, nullable=False)
    data_fine = Column(DateTime, nullable=False)
    note = Column(Text, nullable=True)
    stato_approvazione = Column(String(20), default="In Attesa") # In Attesa, Approvata, Rifiutata
    
    user = relationship("User", backref="assenze")

class Settings(Base):
    __tablename__ = 'settings'
    id = Column(Integer, primary_key=True)
    # Traccar
    traccar_url = Column(String(200), default="http://demo.traccar.org")
    traccar_user = Column(String(100), nullable=True)
    traccar_pass = Column(String(100), nullable=True)
    # Gmail / Email
    gmail_user = Column(String(100), nullable=True)
    gmail_pass = Column(String(100), nullable=True) # App Password
    # Speed Limits (km/h)
    speed_limit_urban = Column(Integer, default=50)
    speed_limit_extra_urban = Column(Integer, default=90)
    speed_limit_highway = Column(Integer, default=130)
