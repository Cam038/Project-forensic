import os
import re
import stripe
import requests

# D3 - format attendu d'un identifiant de session Stripe Checkout
CHECKOUT_SESSION_ID_PATTERN = re.compile(r"^cs_(test|live)_[A-Za-z0-9]+$")


def _api_key():
    # D6 - la cle n'est jamais ecrite dans le code : elle vient uniquement de l'environnement
    api_key = os.getenv('STRIPE_API_KEY')
    if not api_key:
        raise RuntimeError("STRIPE_API_KEY is not set")
    return api_key


def create_checkout(reference, name, unit_price, quantity, confirmation_secret):
    """
        Create Stripe checkout
        Documentation: https://docs.stripe.com/checkout/quickstart?client=react&lang=python
    """
    
    stripe.api_key = _api_key()
    origin_host = os.getenv('APP_ORIGIN_HOST')
    return stripe.checkout.Session.create(
        mode='payment',
        success_url=f"{origin_host}/booking/{reference}?checkout_confirmation_secret={confirmation_secret}",
        cancel_url=origin_host,
        metadata={'booking_reference': reference},
        line_items=[
            {
                'quantity': quantity,
                'price_data': {
                    'currency': 'EUR',
                    'unit_amount': round(unit_price * 100),
                    'product_data': {
                        'name': name,
                    },
                },
            },
        ],
    )


def is_checkout_paid(checkout_session_id):
    """
        D4 - verifie aupres de Stripe (cote serveur) que la session a bien ete payee
    """
    if not checkout_session_id or not CHECKOUT_SESSION_ID_PATTERN.match(checkout_session_id):
        return False

    stripe.api_key = _api_key()
    session = stripe.checkout.Session.retrieve(checkout_session_id)
    return session.payment_status == "paid"


def get_checkout_lines(checkout_session_id):
    # D3 - on refuse tout identifiant qui n'a pas le format Stripe (../, #, ?, /...) avant de construire l'URL
    if not checkout_session_id or not CHECKOUT_SESSION_ID_PATTERN.match(checkout_session_id):
        raise ValueError("Invalid checkout session ID")

    url = f"https://api.stripe.com/v1/checkout/sessions/{checkout_session_id}/line_items"

    session = requests.Session()
    session.auth = (_api_key(), "")
    return session.get(url, timeout=10).json()["data"]
