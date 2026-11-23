from pathlib import Path
from flask import Blueprint, request, send_from_directory, abort

uploads_api = Blueprint('uploads', __name__)

# D2 - dossier autorise, en chemin absolu
UPLOAD_FOLDER = Path(__file__).resolve().parents[2] / "uploads"


@uploads_api.route('/')
def get_upload():
   filename = request.args.get("name")
   if not filename:
      abort(400, description="Missing filename")

   # D2 - send_from_directory refuse tout chemin qui sort de UPLOAD_FOLDER (../, chemin absolu) -> 404
   return send_from_directory(str(UPLOAD_FOLDER), filename)
