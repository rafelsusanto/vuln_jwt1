from django.urls import path, include
from .views import NoSignatureTokenObtainPairView  # Corrected import
from . import views

urlpatterns = [
    path('login/', views.my_login_view, name='login'),
    path('', views.home_page, name='home_page'),
    path('admin/', views.admin_page, name='admin_page'),
    path('logout/', views.logout, name='logout'),
    path('api/token/', NoSignatureTokenObtainPairView.as_view(), name='token_obtain_pair'),

]