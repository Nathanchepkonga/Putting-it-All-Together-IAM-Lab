#!/usr/bin/env python3

from flask import jsonify, make_response, request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


@app.before_request
def check_log_in_status():
    login_routes = ['recipes', 'check_session', 'logout']
    if request.endpoint in  login_routes:
        if 'user_id' not in session or session['user_id'] is None:
            return make_response(jsonify({'error': 'Please log in'}), 401)
class Signup(Resource):
    def post(self):
        data  = request.get_json()
        if ('username' not in data or 'password' not in data and 'password_confirmation' not in data):
            return make_response(jsonify({
                'error': {
                    'message': 'username and password required'
                }
            }), 422)
        
        # Create a new user
        new_user = User(
            username = data.get('username'),
            image_url = data.get('image_url', None),
            bio  = data.get('bio', None)
        )

        # Hash password and store it
        new_user.password_hash = data.get('password')

        # Add user to database
        db.session.add(new_user)
        db.session.commit()

        # Save user ID to session
        session['user_id'] = new_user.id

        response = make_response(jsonify({
            'user_id': new_user.id,
            'username': new_user.username,
            'image_url': new_user.image_url,
            'bio': new_user.bio
        }),  201)

        return response

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = User.query.filter(User.id == user_id).first()

            if user:
                return make_response(jsonify({
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }), 200)

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return make_response(jsonify({
                'error': {
                    'message': 'Missing credentials'
                }
            }), 400)
        
        user = User.query.filter(User.username == username).first()
        
        # Authenticate user password
        if user is None:
            return make_response(jsonify({
            'error': {
                'message':  'User does not exist'
                }
            }), 401)
        
        if user and not user.authenticate(password):
            return make_response(jsonify({
                'error': {
                    'message': 'Invalid credentials'
                }
            }))
        
        # If authentication succeeds, 
        session['user_id'] = user.id

        return  make_response(jsonify({
            'id': user.id,
            'username': user.username,
            'image_url': user.image_url,
            'bio': user.bio
        }), 200)
    
        

class Logout(Resource):
    def delete(self):
        if 'user_id' in session and session['user_id'] is not None:
            session.pop('user_id', None)
            return make_response(jsonify({}), 204)

class RecipeIndex(Resource):
    def get(self):
        if 'user_id' in session:
            user = User.query.filter_by(id = session['user_id']).first()

            if user:
                recipes = [recipe.to_dict() for recipe in Recipe.query.filter(Recipe.user_id == user.id).all()]
                return make_response(jsonify(recipes), 200)
            else:
                return make_response(jsonify({
                    'error': {
                        'message': 'User does not exist'
                    }
                }))
        
    def post(self):
        
        data = request.get_json()

        title = data['title']
        instructions = data['instructions']
        minutes_to_complete = data['minutes_to_complete']

        if 'title' not in data or 'instructions' not in data or 'minutes_to_complete' not in data:
            return  make_response(jsonify({
                'error': {
                    'message': 'Missing required fields'
                }
            }), 422)
        
        if 'title' in data and 'instructions' in data and  'minutes_to_complete' in data:
            if len(title) > 0  and len(instructions) >= 50 and isinstance(minutes_to_complete, int):
                new_recipe = Recipe(title=title, instructions=instructions, minutes_to_complete=minutes_to_complete)

                # Associate recipe with the logged in user
                new_recipe.user_id = session['user_id']

                # Add the new recipe to the database
                db.session.add(new_recipe)
                db.session.commit()

                return make_response(jsonify({
                        'title': new_recipe.title,
                        'instructions': new_recipe.instructions,
                        'minutes_to_complete': new_recipe.minutes_to_complete
                }), 201)
            else:
                return make_response(jsonify({
                    'error': {
                        'message':  'Invalid input'
                    }
                }), 422)


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)