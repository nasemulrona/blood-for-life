from django.urls import path, include
from rest_framework import routers
from rest_framework_simplejwt.views import TokenRefreshView
from .views import CustomTokenObtainPairView, CustomLoginView, CustomRegisterView
from django.conf.urls.i18n import i18n_patterns
from django.views.i18n import set_language
from .views import send_blood_notification, notify_blood_need
from . import views

from .views import (
    RegisterAPI, LogoutAPI, UserViewSet, DonorProfileViewSet, 
    BloodBankViewSet, DonationRequestViewSet, DonationHistoryViewSet,
    donor_dashboard, admin_dashboard, home, public_home, simple_logout,
    # Add these imports
    admin_blood_banks, admin_donors, admin_requests, approve_request, reject_request,
    donor_profile, make_donation_request, donation_requests, donation_history,
    search_donors  # ADD THIS IMPORT
)

# Router for API endpoints
router = routers.DefaultRouter()
router.register('users', UserViewSet)
router.register('profiles', DonorProfileViewSet, basename='profiles')
router.register('banks', BloodBankViewSet)
router.register('requests', DonationRequestViewSet, basename='requests')
router.register('donations', DonationHistoryViewSet, basename='donations')

# URL patterns
urlpatterns = [
    # Home page (public for non-authenticated, dashboard for authenticated)
    path('', public_home, name='public_home'),
    path('dashboard/', home, name='home'),
    path('i18n/setlang/', set_language, name='set_language'),
     # Notification URLs
    path('admin/send-notification/', send_blood_notification, name='blood_notification'),
    path('admin/notify-blood-need/<str:blood_group>/', notify_blood_need, name='notify_blood_need'),
    
    
    # Template-based authentication
    path('login/', CustomLoginView.as_view(), name='login_page'),
    path('register/', CustomRegisterView.as_view(), name='register_page'),
    path('logout/', simple_logout, name='logout'),

    # API endpoints
    path('api/', include(router.urls)),
    
    # Authentication endpoints
    path('api/auth/register/', RegisterAPI.as_view(), name='register'),
    path('api/auth/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/logout/', LogoutAPI.as_view(), name='api_logout'),

    # Legacy dashboards (redirect to new home)
    path('dashboard/donor/', donor_dashboard, name='donor_dashboard'),
    path('dashboard/admin/', admin_dashboard, name='admin_dashboard'),
    
    # Admin Management URLs
    path('admin/blood-banks/', admin_blood_banks, name='admin_blood_banks'),
    path('admin/donors/', admin_donors, name='admin_donors'),
    path('admin/requests/', admin_requests, name='admin_requests'),
    path('admin/requests/<int:request_id>/approve/', approve_request, name='approve_request'),
    path('admin/requests/<int:request_id>/reject/', reject_request, name='reject_request'),
    
    # Donor Feature URLs
    path('donor/profile/', donor_profile, name='donor_profile'),
    path('donor/make-request/', make_donation_request, name='make_donation_request'),
    path('donor/requests/', donation_requests, name='donation_requests'),
    path('donor/history/', donation_history, name='donation_history'),
    
    # Search Functionality URL - ADD THIS LINE
    path('search/donors/', search_donors, name='search_donors'),
    path('cancel-request/<int:request_id>/', views.cancel_donation_request, name='cancel_donation_request'),
]