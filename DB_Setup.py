import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import datetime
from sqlalchemy import Column, Integer, DateTime
from sqlalchemy import DateTime
from sqlalchemy import func

Base = declarative_base()


class StorageLogin(Base):
    __tablename__ = 'storage_tb'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False)
    password = Column(String(30), nullable=False)
    email = Column(String(50),nullable=False)

class FileMetadata(Base):

    __tablename__= "fileMetadata"
    id = Column(Integer, primary_key=True)
    file_name=Column(String(50),nullable=False)
    loc=Column(String(550),nullable=False)
    created = Column(DateTime, default=datetime.datetime.utcnow)
    modified = Column(DateTime, default=datetime.datetime.utcnow)






    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'username': self.name,
            'id': self.id,
            'password': self.password,
            'email': self.email,
        }

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id':self.id,
            'file_name': self.file_name,
            'loc': self.loc,
            'modified': self.modified,
            'created': self.created,

        }

engine = create_engine('sqlite:///Storage.db')

Base.metadata.create_all(engine)
