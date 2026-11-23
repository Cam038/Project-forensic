#!/bin/sh
apache2ctl -D FOREGROUND &
# D8 - serveur WSGI de production (plus le serveur de developpement Werkzeug)
exec gunicorn --workers 2 --bind 127.0.0.1:9001 app:app
