# auth_app/views.py
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .decorators import jwt_required
from django.utils import timezone
from .models import BlacklistedToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
import jwt
from django.contrib.auth import get_user_model
from django.conf import settings

class NoSignatureTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        # The original validation logic
        data = super().validate(attrs)

        # Override validation here to accept 'none' algorithm
        # WARNING: This is insecure and for educational purposes only
        self.user = self.user or self.authenticate_no_signature(attrs)

        # Custom handling to return token for 'none' algorithm without validation
        if self.user:
            refresh = self.get_token(self.user)

            data['refresh'] = str(refresh)
            data['access'] = str(refresh.access_token)

            if api_settings.UPDATE_LAST_LOGIN:
                update_last_login(None, self.user)

        return data

    def authenticate_no_signature(self, attrs):
        # Simulate successful authentication without signature validation
        # This is where you'd bypass signature checks (for demonstration only)
        # You might simulate fetching a user object based on some criteria
        # For simplicity, this example doesn't implement a real authentication bypass
        return None  # Replace None with actual user object in a real scenario

class NoSignatureTokenObtainPairView(TokenObtainPairView):
    serializer_class = NoSignatureTokenObtainPairSerializer

from django.conf import settings
import jwt
from django.utils import timezone
from django.shortcuts import redirect, render
from django.urls import reverse
from django.contrib.auth import authenticate

def my_login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            payload = {
                'user_id': user.id,
                'username': user.username,
                # Ensure you use an appropriate expiration time
                'exp': timezone.now() + timezone.timedelta(minutes=5)
            }
            print(jwt.__file__)
            # Encode the token without a key to simulate the 'none' algorithm for educational purposes
            token = jwt.encode(payload, key=None, algorithm='none')

            # Ensure the token is a string if you are setting it in a cookie
            token_str = token if isinstance(token, str) else token.decode('utf-8')

            response = redirect(reverse('home_page'))
            response.set_cookie(key='access', value=token_str, httponly=True)
            return response
        else:
            # Your logic for failed authentication
            render(request, 'login.html')
    # Your logic for handling non-POST requests
    return render(request, 'login.html')


@jwt_required
def home_page(request):
    # Accessible only when logged in
    return render(request, 'home.html')

@jwt_required
def admin_page(request):
    token = request.COOKIES.get('access', None)
    if token:
        try:
            # Assuming you're using the 'none' algorithm for demonstration
            payload = jwt.decode(token, options={"verify_signature": False}, algorithms=['none'])
            user_id = payload.get('user_id')

            # Check if the user exists and is an admin
            User = get_user_model()
            try:
                user = User.objects.get(id=user_id, is_staff=True)
                # User is an admin
                return render(request, 'admin.html')
            except User.DoesNotExist:
                # User does not exist or is not an admin
                return render(request, '403.html')

        except jwt.exceptions.DecodeError as e:
            # Handle decode error (token invalid, etc.)
            print(f"JWT decode error: {e}")
            return redirect('/login/')  # or handle as appropriate
    else:
        # If there's no token, redirect to login
        return redirect('/login/')

def logout(request):
    token = request.COOKIES.get('access', None)
    if token:
        # Directly parse the token without verification
        try:
            # Decode the token without verification
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            if 'exp' in decoded_token:
                expires_at = timezone.datetime.fromtimestamp(decoded_token['exp'], tz=timezone.utc)
            else:
                # Default to immediate expiration if 'exp' claim is missing
                expires_at = timezone.now()

            # Add the token to the blacklist
            BlacklistedToken.objects.create(token=token, expires_at=expires_at)

        except jwt.exceptions.DecodeError:
            # Handle cases where the token is malformed and cannot be decoded
            pass  # Optionally log this event or handle it as needed

    response = redirect('/login/')  # Redirect to the login page
    response.delete_cookie('access')  # Remove the 'access' cookie
    return response
