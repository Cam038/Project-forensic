from flask import Flask
from werkzeug.serving import WSGIRequestHandler
from flask_cors import CORS
from database.init import db
from database.seed import seed_database

from api.rooms.rooms_models import Room
from api.rooms.rooms_api import rooms_api
from api.users.users_models import User
from api.users.users_api import users_api
from api.auth.auth_api import auth_api
from api.bookings.bookings_api import bookings_api
from api.bookings.bookings_models import Booking
from api.uploads.uploads_api import uploads_api
from api.webhooks.webhooks_api import webhooks_api
import os


app = Flask(__name__)
app.config.from_pyfile('config.py')

# Add CORS to all requests
CORS(app, origins=app.config["CORS_ORIGINS"])

# Initialize database
db.init_app(app)
with app.app_context():
   db.create_all()
   seed_database()

# Routes
app.register_blueprint(rooms_api, url_prefix='/rooms')
app.register_blueprint(users_api, url_prefix='/users')
app.register_blueprint(auth_api, url_prefix='/auth')
app.register_blueprint(bookings_api, url_prefix='/bookings')
app.register_blueprint(uploads_api, url_prefix='/uploads')
app.register_blueprint(webhooks_api, url_prefix='/webhooks')


# D7 - en-tetes de securite sur toutes les reponses
@app.after_request
def add_security_headers(response):
   response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
   response.headers["X-Content-Type-Options"] = "nosniff"
   response.headers["X-Frame-Options"] = "DENY"
   return response


# D8 - le serveur de developpement n'annonce plus "Werkzeug/x.y Python/x.y" dans l'en-tete Server
class NoBannerRequestHandler(WSGIRequestHandler):
   def version_string(self):
      return "HackBNB"


@app.route('/', methods=['GET'])
def welcome():
   return "Welcome on API"


if __name__ == '__main__':
   app.run(
      # D8 - serveur de developpement uniquement, debogueur Werkzeug desactive par defaut
      debug=os.getenv("FLASK_DEBUG") == "1",
      host="0.0.0.0",
      port=9001,
      request_handler=NoBannerRequestHandler,
   )
