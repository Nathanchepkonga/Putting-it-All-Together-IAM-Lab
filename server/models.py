from sqlalchemy import CheckConstraint
from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationship mapping user to recipes
    recipes = db.relationship('Recipe', back_populates='user', cascade='all, delete-orphan')

    # Serialize rules
    serialize_rules = ('-recipes.user',)

    # Password encryption
    @property
    def password_hash(self):
        raise AttributeError({
            'error': {
                'type': 'AttributeError',
                'message': 'Password is not a readable attribute'
            }
        })
    
    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password)

    # Authenticator
    def  authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    def __repr__(self):
        return f'<ID: {self.id},  Username: {self.username}, Bio:  {self.bio}>'


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id  = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    # Relationship mapping recipe to a user
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', back_populates='recipes')

    # Serialize rules
    serialize_rules = ('-user.recipes',)

    # Add CheckConstraints
    @validates('title')
    def validate_title(self, key, title):
        if not title or len(title) == 0:
            raise ValueError({
                'error': {
                    'message': 'Title cannot be empty'
                }
            })
        return title
    
    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) == 0:
            raise ValueError({
                'error': {
                    'message': 'Instructions cannot be empty'
                }
            })
        
        if len(instructions) < 50:
            raise ValueError({
                'error': {
                    'message': 'Instructions must be at least 50 characters long'
                }
            })
        
        return instructions
    