from flask import Flask, jsonify, request, Response
from flask_restful import reqparse, abort, Api, Resource
from flask.ext.pymongo import PyMongo
import datetime
from flask.ext.login import login_required
from bson.objectid import ObjectId
import json
import flask
import httplib2
from apiclient import discovery
from oauth2client import client
from flask.ext.login import login_user, logout_user
from flask.ext.login import LoginManager
from flask.ext.cors import CORS

app = Flask(__name__)
CORS(app)

api = Api(app)
mongo = PyMongo(app)
app.secret_key = 'super-secret-text'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

parser = reqparse.RequestParser()
parser.add_argument('title', type=str, help="Title is required", required=True)
parser.add_argument('body', type=str, help="Body is required.", required=True)
parser.add_argument('tags', type=str, action="append")

class User():
    def __init__(self, username):
        self.username = username

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return  self.username

@login_manager.user_loader
def load_user(user_id):
    u = mongo.db.users.find_one({"_id": user_id})
    if not u:
        return None
    return User(u['_id'])

@app.route('/login')
def login():
  if 'credentials' not in flask.session:
    return flask.redirect(flask.url_for('oauth2callback'))
  credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
  if credentials.access_token_expired:
    return flask.redirect(flask.url_for('oauth2callback'))
  else:
    http_auth = credentials.authorize(httplib2.Http())
    return flask.redirect(flask.url_for("posts"))

@app.route('/logout')
def logout():
    logout_user()
    return flask.redirect(flask.url_for('login'))

@app.route('/oauth2callback')
def oauth2callback():
  flow = client.flow_from_clientsecrets(
      'client_secrets.json',
      scope='email',
      redirect_uri=flask.url_for('oauth2callback', _external=True))
  if 'code' not in flask.request.args:
    auth_uri = flow.step1_get_authorize_url()
    return flask.redirect(auth_uri)
  else:
    auth_code = flask.request.args.get('code')
    credentials = flow.step2_exchange(auth_code)
    flask.session['credentials'] = credentials.to_json()
    email = credentials.id_token['email']
    if email != "canice.lu@gmail.com":
        return flask.redirect(auth_uri)
    user = mongo.db.users.find_one({"_id":email})
    if not user:
        user = mongo.db.users.insert_one({"_id":email})
    login_user(User(user['_id']))
    return flask.redirect(flask.url_for('login'))


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        elif isinstance(o, datetime.datetime):
            return o.strftime("%Y-%m-%d %H:%M:%S")
        return json.JSONEncoder.default(self, o)


class PostList(Resource):
    def get(self):
        data = []
        posts = mongo.db.posts.find()
        for post in posts:
            post['id'] = post['_id']
            data.append(post)
        return Response(response=json.dumps({"post":data}, cls=JSONEncoder), 
                        status=200, 
                        mimetype="application/json")
    
    @login_required
    def post(self):
        args = parser.parse_args()
        args.update({"created": datetime.datetime.utcnow()})
        mongo.db.posts.insert_one(args)
        return Response(response=json.dumps({"post":args}, cls=JSONEncoder), 
                        status=200, 
                        mimetype="application/json")


class Post(Resource):
    def get(self, post_id):
        """
            return 400 if the it is not an invalid objectid
            return 404 if there is no such objectid
        """
        post = mongo.db.posts.find_one_or_404(post_id)
        return Response(response=json.dumps({"post":post}, cls=JSONEncoder), 
                        status=200, 
                        mimetype="application/json")

    @login_required
    def delete(self, post_id):
        post = mongo.db.posts.remove({"_id":post_id})
        return Response(response=post, 
                        status=200, 
                        mimetype="application/json")

    @login_required
    def put(self, post_id):
        args = parser.parse_args()
        args.update({"updated": datetime.datetime.utcnow()})
        args.update({"_id": post_id})
        post = mongo.db.posts.save(args)
        return Response(response=json.dumps({"post":post}, cls=JSONEncoder), 
                        status=200, 
                        mimetype="application/json")

##
## Actually setup the Api resource routing here
##
api.add_resource(PostList, '/posts', endpoint="posts")
api.add_resource(Post, '/post/<ObjectId:post_id>')

if __name__ == '__main__':
    app.run(debug=True)