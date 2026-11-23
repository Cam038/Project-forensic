import os
import stripe
from flask import jsonify, Blueprint, request

from database.init import db
from api.bookings.bookings_models import Booking

webhooks_api = Blueprint('webhooks', __name__)


@webhooks_api.route('/stripe', methods=['POST'])
def stripe_webhook():
    """
    D4 - Webhook Stripe : seule source de confiance pour passer une reservation en "payee".
    La signature de l'en-tete Stripe-Signature est verifiee avec STRIPE_WEBHOOK_SECRET.
    """

    webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    if not webhook_secret:
        return {'error': 'Webhook not configured'}, 503

    payload = request.get_data()
    signature = request.headers.get('Stripe-Signature')
    if not signature:
        return {'error': 'Missing Stripe-Signature header'}, 400

    try:
        event = stripe.Webhook.construct_event(payload, signature, webhook_secret)
    except (ValueError, stripe.SignatureVerificationError):
        return {'error': 'Invalid signature'}, 400

    if event['type'] in ('checkout.session.completed', 'checkout.session.async_payment_succeeded'):
        session = event['data']['object'].to_dict()
        if session.get('payment_status') == 'paid':
            booking = Booking.query.filter_by(stripe_checkout_session_id=session.get('id')).first()
            if booking and not booking.is_paid:
                booking.is_paid = True
                db.session.commit()

    return jsonify({'received': True})
