"""
Tests de non-regression securite HackBNB (failles D1 a D8 du rapport d'audit).

Lancement (depuis le dossier back/) :
    pip install -r requirements.txt pytest
    python -m pytest tests/ -v

Aucun appel reseau : les appels a Stripe sont simules (monkeypatch).
Chaque test reproduit l'attaque du rapport et verifie qu'elle echoue.
"""
import hashlib
import hmac
import json
import os
import re
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

BACK_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = BACK_DIR.parent
WEBHOOK_SECRET = "whsec_test_secret_pour_les_tests"


@pytest.fixture(scope="session")
def app():
    os.environ["STRIPE_API_KEY"] = "cle_factice_pour_les_tests"
    os.environ["STRIPE_WEBHOOK_SECRET"] = WEBHOOK_SECRET
    os.environ["APP_ORIGIN_HOST"] = "http://localhost:9000"
    os.chdir(BACK_DIR)
    sys.path.insert(0, str(BACK_DIR))
    db_file = BACK_DIR / "instance" / "database.sqlite"
    if db_file.exists():
        db_file.unlink()
    import app as app_module
    app_module.app.config["TESTING"] = True
    yield app_module.app
    if db_file.exists():
        db_file.unlink()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def bookings_module(app):
    import api.bookings.bookings_api as module
    return module


def _new_booking(client, bookings_module, monkeypatch, session_id):
    """Cree une reservation avec une session Stripe simulee et renvoie (reference, secret)."""
    captured = {}

    def fake_create_checkout(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(id=session_id, url="https://checkout.stripe.com/fake")

    monkeypatch.setattr(bookings_module, "create_checkout", fake_create_checkout)
    created_at = int(time.time())
    res = client.post("/bookings/", json={
        "roomId": 3, "arrivalDate": "2026-12-01", "departureDate": "2026-12-03", "guestsCount": 2,
    })
    assert res.status_code == 200, res.get_json()
    return res.get_json()["reference"], captured["confirmation_secret"], created_at


# ---------------------------------------------------------------- D1 Injection SQL
def test_d1_filtre_normal_preserve(client):
    rooms = client.get("/rooms/?category=ski").get_json()
    assert len(rooms) == 2


@pytest.mark.parametrize("payload", ["' OR 1=1 --", "' OR 1=2 --",
                                     "test' UNION SELECT 1,2,3,4,5,6,7,8 FROM users --"])
def test_d1_injection_sql_neutralisee(client, payload):
    res = client.get("/rooms/", query_string={"category": payload})
    assert res.status_code == 200
    assert res.get_json() == []          # recherche litterale : aucune chambre


# ---------------------------------------------------------------- D2 Path traversal
def test_d2_image_legitime(client):
    res = client.get("/uploads/?name=room-1.jpg")
    assert res.status_code == 200
    assert len(res.data) == 809218


@pytest.mark.parametrize("payload", ["../config.py", "../app.py", "../services/stripe.py",
                                     "../api/bookings/bookings_api.py", "../../etc/passwd",
                                     "/etc/passwd", "..%2Fconfig.py"])
def test_d2_traversee_bloquee(client, payload):
    res = client.get("/uploads/", query_string={"name": payload})
    assert res.status_code == 404
    assert b"SQLALCHEMY" not in res.data and b"root:" not in res.data and b"import" not in res.data


def test_d2_parametre_absent(client):
    assert client.get("/uploads/").status_code == 400


# ---------------------------------------------------------------- D3 Session Stripe
def test_d3_session_id_du_client_ignore(app, client, bookings_module, monkeypatch):
    ref, _, _ = _new_booking(client, bookings_module, monkeypatch, "cs_test_SessionDeA")
    from api.bookings.bookings_models import Booking
    from database.init import db
    with app.app_context():
        booking = Booking.query.filter_by(reference=ref).first()
        booking.is_paid = True
        db.session.commit()

    calls = []
    monkeypatch.setattr(bookings_module, "get_checkout_lines",
                        lambda sid: calls.append(sid) or [{"id": "li_" + sid}])
    for injected in ["cs_test_SessionDeB", "../../customers#", "../../customers/cus_X/payment_methods#"]:
        res = client.get(f"/bookings/{ref}/checkout-lines", query_string={"checkout_session_id": injected})
        assert res.status_code == 200
    assert calls == ["cs_test_SessionDeA"] * 3   # toujours la session de la reservation, jamais celle du client


@pytest.mark.parametrize("bad_id", ["../../customers#", "cs_test_x/../../customers", "cs_test_x?expand=1", "", None])
def test_d3_service_refuse_un_id_malforme(app, monkeypatch, bad_id):
    import services.stripe as stripe_service
    urls = []
    monkeypatch.setattr("requests.Session.get", lambda self, url, **kw: urls.append(url))
    with pytest.raises(ValueError):
        stripe_service.get_checkout_lines(bad_id)
    assert urls == []                              # aucune requete partie vers Stripe


# ---------------------------------------------------------------- D4 Secret predictible
def test_d4_secret_non_predictible(client, bookings_module, monkeypatch):
    _, secret, created_at = _new_booking(client, bookings_module, monkeypatch, "cs_test_D4a")
    candidates = {hashlib.sha512(str(ts).encode()).hexdigest() for ts in range(created_at - 5, created_at + 6)}
    assert secret not in candidates
    assert len(secret) >= 43                       # 32 octets aleatoires en base64url


def test_d4_attaque_timestamp_refusee(client, bookings_module, monkeypatch):
    ref, _, created_at = _new_booking(client, bookings_module, monkeypatch, "cs_test_D4b")
    monkeypatch.setattr(bookings_module, "is_checkout_paid", lambda sid: False, raising=False)
    for ts in range(created_at - 5, created_at + 6):
        forged = hashlib.sha512(str(ts).encode()).hexdigest()
        res = client.post(f"/bookings/{ref}/confirm-checkout", json={"confirmationSecret": forged})
        assert res.status_code != 200
    assert client.get(f"/bookings/{ref}").get_json()["is_paid"] is False


def test_d4_bon_secret_mais_non_paye_chez_stripe(client, bookings_module, monkeypatch):
    ref, secret, _ = _new_booking(client, bookings_module, monkeypatch, "cs_test_D4c")
    monkeypatch.setattr(bookings_module, "is_checkout_paid", lambda sid: False, raising=False)
    res = client.post(f"/bookings/{ref}/confirm-checkout", json={"confirmationSecret": secret})
    assert res.status_code == 403
    assert client.get(f"/bookings/{ref}").get_json()["is_paid"] is False


def test_d4_paiement_reel_accepte(client, bookings_module, monkeypatch):
    ref, secret, _ = _new_booking(client, bookings_module, monkeypatch, "cs_test_D4d")
    monkeypatch.setattr(bookings_module, "is_checkout_paid", lambda sid: sid == "cs_test_D4d", raising=False)
    res = client.post(f"/bookings/{ref}/confirm-checkout", json={"confirmationSecret": secret})
    assert res.status_code == 200
    assert client.get(f"/bookings/{ref}").get_json()["is_paid"] is True


def _signed(payload: bytes, secret=WEBHOOK_SECRET):
    t = str(int(time.time()))
    sig = hmac.new(secret.encode(), f"{t}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={t},v1={sig}"


def _event(session_id):
    return json.dumps({"id": "evt_test", "object": "event", "type": "checkout.session.completed",
                       "data": {"object": {"id": session_id, "object": "checkout.session",
                                           "payment_status": "paid"}}}).encode()


def test_d4_webhook_sans_signature_refuse(client, bookings_module, monkeypatch):
    ref, _, _ = _new_booking(client, bookings_module, monkeypatch, "cs_test_D4e")
    res = client.post("/webhooks/stripe", data=_event("cs_test_D4e"), content_type="application/json")
    assert res.status_code in (400, 403)
    res = client.post("/webhooks/stripe", data=_event("cs_test_D4e"), content_type="application/json",
                      headers={"Stripe-Signature": _signed(_event("cs_test_D4e"), "whsec_faux")})
    assert res.status_code in (400, 403)
    assert client.get(f"/bookings/{ref}").get_json()["is_paid"] is False


def test_d4_webhook_signe_valide_le_paiement(client, bookings_module, monkeypatch):
    ref, _, _ = _new_booking(client, bookings_module, monkeypatch, "cs_test_D4f")
    payload = _event("cs_test_D4f")
    res = client.post("/webhooks/stripe", data=payload, content_type="application/json",
                      headers={"Stripe-Signature": _signed(payload)})
    assert res.status_code == 200
    assert client.get(f"/bookings/{ref}").get_json()["is_paid"] is True


# ---------------------------------------------------------------- D5 E-mails des hotes
def test_d5_email_hote_absent(client):
    room = client.get("/rooms/2").get_json()
    assert room["host"] == {"id": 1, "name": "John Doe"}
    for r in client.get("/rooms/").get_json():
        assert "email" not in r["host"]
    assert b"@" not in client.get("/rooms/").data


# ---------------------------------------------------------------- D6 Cle Stripe
def test_d6_aucune_cle_stripe_dans_le_depot():
    pattern = re.compile(rb"(sk|rk)_(test|live)_[A-Za-z0-9]{10,}")
    found = []
    for path in PROJECT_DIR.rglob("*"):
        parts = set(path.parts)
        if path.is_dir() or {".git", "node_modules", "__pycache__", "dist"} & parts or path.name == ".env":
            continue
        if pattern.search(path.read_bytes()):
            found.append(str(path.relative_to(PROJECT_DIR)))
    assert found == []


def test_d6_env_ignore_par_git():
    gitignore = (PROJECT_DIR / ".gitignore").read_text()
    assert re.search(r"^\.env\s*$", gitignore, re.M)


# ---------------------------------------------------------------- D7 XSS et en-tetes
@pytest.mark.parametrize("url", ["/", "/rooms/", "/rooms/2", "/uploads/?name=room-1.jpg"])
def test_d7_entetes_de_securite(client, url):
    h = client.get(url).headers
    assert "default-src 'self'" in h.get("Content-Security-Policy", "")
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("X-Frame-Options") == "DENY"


def test_d7_plus_de_html_injecte_dans_le_front():
    for f in ["front/src/pages/room/Room.tsx", "front/src/pages/booking/Booking.tsx"]:
        assert "dangerouslySetInnerHTML" not in (PROJECT_DIR / f).read_text(encoding="utf-8")


def test_d7_descriptions_en_texte_brut(client):
    for r in client.get("/rooms/").get_json():
        assert "<" not in r["description"]


def test_d7_entetes_apache_prod():
    conf = (PROJECT_DIR / "apache/apache-prod.conf").read_text()
    for h in ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]:
        assert re.search(rf"Header always set {h}", conf)


# ---------------------------------------------------------------- D8 En-tete Server
def test_d8_entete_server_neutre_serveur_reel(app):
    # vrai serveur HTTP (meme gestionnaire que `python3 app.py`), pas le client de test
    import threading
    import requests
    import app as app_module
    from werkzeug.serving import make_server
    handler = getattr(app_module, "NoBannerRequestHandler", None)
    server = make_server("127.0.0.1", 0, app, **({"request_handler": handler} if handler else {}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        res = requests.get(f"http://127.0.0.1:{server.server_port}/rooms/", timeout=5)
        values = res.raw.headers.getlist("Server")
    finally:
        server.shutdown()
    assert values, "en-tete Server absent"
    for value in values:
        assert not re.search(r"werkzeug|python|\d", value, re.I), values


@pytest.mark.parametrize("conf", ["apache/apache-prod.conf", "apache/apache-dev.conf"])
def test_d8_apache_masque_sa_version(conf):
    text = (PROJECT_DIR / conf).read_text()
    assert re.search(r"^\s*ServerTokens\s+Prod\s*$", text, re.M)
    assert re.search(r"^\s*ServerSignature\s+Off\s*$", text, re.M)


def test_d8_prod_sur_gunicorn():
    entrypoint = (PROJECT_DIR / "prod.entrypoint.sh").read_text()
    assert "gunicorn" in entrypoint and "python3 app.py" not in entrypoint
