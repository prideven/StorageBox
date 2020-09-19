import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class StorageLogin(Base):
    __tablename__ = 'storage_tb'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False)
    password = Column(String(30), nullable=False)
    email = Column(String(50),nullable=False)


    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'username': self.name,
            'id': self.id,
            'password': self.password,
            'email': self.email,
        }


engine = create_engine('sqlite:///Storage.db')

Base.metadata.create_all(engine)
