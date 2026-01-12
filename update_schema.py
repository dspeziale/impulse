from sqlalchemy import create_engine, text
import os
from dotenv import load_dotenv
from api.models import Base, Automezzo, Cantiere, Timbratura, Assenza

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL')

if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    
    engine = create_engine(DATABASE_URL, connect_args={'sslmode': 'require'})
    
    print("Creating new tables...")
    Base.metadata.create_all(engine)
    print("Tables created successfully.")
else:
    print("DATABASE_URL not set.")
