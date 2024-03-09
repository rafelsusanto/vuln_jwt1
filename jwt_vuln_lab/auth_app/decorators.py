from django.shortcuts import redirect
from django.conf import settings
import jwt
from django.contrib.auth import get_user_model
from jwt.exceptions import DecodeError, ExpiredSignatureError
from .models import BlacklistedToken

def jwt_required(f):
    def wrap(request, *args, **kwargs):
        User = get_user_model()
        token = request.COOKIES.get('access', None)
        if token:
            try:
                # Check if token is blacklisted
                if BlacklistedToken.objects.filter(token=token).exists():
                    # Redirect to login if token is blacklisted
                    return redirect(settings.LOGIN_URL)
                
                # Decode token without signature verification
                payload = jwt.decode(token, options={"verify_signature": False}, algorithms=['none', 'HS256'])
                user_id = payload.get('user_id')

                # Ensure the payload has the expected fields
                if user_id is None:
                    raise DecodeError("Invalid payload structure.")

                user = User.objects.get(id=user_id)
                request.user = user
                return f(request, *args, **kwargs)
            except (DecodeError, ExpiredSignatureError, User.DoesNotExist) as e:
                # Log the error or handle it as needed
                print(f"JWT authentication error: {e}")
                # Consider more explicit handling here
        # Redirect if token is missing or invalid
        return redirect(settings.LOGIN_URL)

    return wrap