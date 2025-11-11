from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import logout, authenticate, login
from django.db import models
from django import forms
from django.views.generic import FormView
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db.models import Count, Sum, Q 
from django.contrib import messages
from django.utils import timezone
from .models import DonationRequest
from django.shortcuts import render, redirect

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import User, DonorProfile, BloodBank, DonationRequest, DonationHistory
from .serializers import (
    UserSerializer, RegisterSerializer, DonorProfileSerializer,
    BloodBankSerializer, DonationRequestSerializer, DonationHistorySerializer
)
from .utils import send_donation_approved_email, send_blood_need_bulk  # Import email utilities

# -------------------------------
# Custom Forms for Template Views
# -------------------------------
class CustomLoginForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter your password'})
    )

class CustomRegisterForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email'})
    )
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Choose a username'})
    )
    first_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First name (optional)'})
    )
    last_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last name (optional)'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter password'})
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm password'})
    )
    role = forms.ChoiceField(
        choices=[('donor', 'Donor'), ('admin', 'Admin')],
        initial='donor',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password2 = cleaned_data.get('password2')
        
        if password and password2 and password != password2:
            raise forms.ValidationError("Passwords don't match")
        
        if password:
            try:
                validate_password(password)
            except ValidationError as e:
                raise forms.ValidationError(e.messages)
        
        return cleaned_data

# Donor Profile Form
class DonorProfileForm(forms.ModelForm):
    class Meta:
        model = DonorProfile
        fields = ['phone', 'blood_group', 'city', 'last_donation', 'profile_photo']
        widgets = {
            'phone': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your phone number'}),
            'blood_group': forms.Select(attrs={'class': 'form-select'}),
            'city': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your city'}),
            'last_donation': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'profile_photo': forms.FileInput(attrs={'class': 'form-control'}),
        }

# Donation Request Form
class DonationRequestForm(forms.ModelForm):
    class Meta:
        model = DonationRequest
        fields = ['blood_group', 'units', 'hospital_name']
        widgets = {
            'blood_group': forms.Select(attrs={'class': 'form-select'}),
            'units': forms.NumberInput(attrs={'class': 'form-control', 'min': 1, 'max': 5}),
            'hospital_name': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'Enter hospital name'
            }),
        }
        
    def clean_units(self):
        units = self.cleaned_data.get('units')
        if units < 1:
            raise forms.ValidationError("Units must be at least 1")
        if units > 5:
            raise forms.ValidationError("Cannot request more than 5 units at once")
        return units

# -------------------------------
# Custom Token Serializer and View
# -------------------------------
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

# -------------------------------
# Custom Permission Classes
# -------------------------------
class IsAdmin(permissions.BasePermission):
    """Allow access only to admin users"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'

# -------------------------------
# Template-based Views
# -------------------------------
class CustomLoginView(FormView):
    template_name = 'core/login.html'
    form_class = CustomLoginForm
    success_url = '/dashboard/'

    def form_valid(self, form):
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']
        
        # Authenticate using email as username
        user = authenticate(username=email, password=password)
        if user is not None:
            login(self.request, user)
            return redirect('/dashboard/?action=login_success')
        else:
            form.add_error(None, 'Invalid email or password')
            return self.form_invalid(form)

class CustomRegisterView(FormView):
    template_name = 'core/register.html'
    form_class = CustomRegisterForm
    success_url = '/login/'

    def form_valid(self, form):
        email = form.cleaned_data['email']
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        first_name = form.cleaned_data.get('first_name', '')
        last_name = form.cleaned_data.get('last_name', '')
        role = form.cleaned_data.get('role', 'donor')
        
        # Get blood group from form data
        blood_group = self.request.POST.get('blood_group', 'O+')

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            form.add_error('email', 'User with this email already exists.')
            return self.form_invalid(form)
        
        if User.objects.filter(username=username).exists():
            form.add_error('username', 'User with this username already exists.')
            return self.form_invalid(form)

        # Create user
        try:
            user = User.objects.create_user(
                email=email,
                username=username,
                password=password,
                first_name=first_name,
                last_name=last_name,
                role=role
            )
            
            # If donor, create donor profile with selected blood group
            if role == 'donor':
                DonorProfile.objects.create(
                    user=user, 
                    blood_group=blood_group  # Use selected blood group
                )
                
            return redirect('/login/?action=register_success')
            
        except Exception as e:
            form.add_error(None, f'Error creating user: {str(e)}')
            return self.form_invalid(form)

@login_required
def home(request):
    """Home page with role-based dashboard cards"""
    context = {}
    
    if request.user.role == 'admin':
        # Admin dashboard data
        context['total_donors'] = User.objects.filter(role='donor').count()
        context['total_requests'] = DonationRequest.objects.count()
        context['pending_requests'] = DonationRequest.objects.filter(status='pending').count()
        context['approved_requests'] = DonationRequest.objects.filter(status='approved').count()
        context['total_banks'] = BloodBank.objects.count()
        context['total_donations'] = DonationHistory.objects.count()
        
        # Calculate total available blood units from all blood banks
        total_units = 0
        for bank in BloodBank.objects.all():
            total_units += (bank.units_a_plus + bank.units_a_minus + bank.units_b_plus + 
                          bank.units_b_minus + bank.units_o_plus + bank.units_o_minus + 
                          bank.units_ab_plus + bank.units_ab_minus)
        context['available_units'] = total_units
        
        # Calculate success rate
        if context['total_requests'] > 0:
            context['success_rate'] = round((context['approved_requests'] / context['total_requests']) * 100)
        else:
            context['success_rate'] = 0
        
        context['banks'] = BloodBank.objects.all()
    else:
        # Donor dashboard data - FIXED VERSION
        try:
            # Use DonorProfile model to get the profile
            donor_profile = DonorProfile.objects.get(user=request.user)
            context['donor_profile'] = donor_profile
            
            # Calculate all counts for donor dashboard
            context['donation_count'] = DonationHistory.objects.filter(donor=request.user).count()
            context['pending_donation_count'] = DonationRequest.objects.filter(
                donor=request.user, 
                status='pending'
            ).count()
            # ADD THESE MISSING VARIABLES
            context['approved_donation_count'] = DonationRequest.objects.filter(
                donor=request.user, 
                status='approved'
            ).count()
            context['rejected_donation_count'] = DonationRequest.objects.filter(
                donor=request.user, 
                status='rejected'
            ).count()
            
            context['donations'] = DonationHistory.objects.filter(donor=request.user)
            context['requests'] = DonationRequest.objects.filter(donor=request.user)
            
            # Recent activities for timeline
            context['recent_activities'] = DonationRequest.objects.filter(
                donor=request.user
            ).order_by('-created_at')[:5]
            
        except DonorProfile.DoesNotExist:
            # Create profile if doesn't exist
            donor_profile = DonorProfile.objects.create(
                user=request.user, 
                blood_group='O+'
            )
            context['donor_profile'] = donor_profile
            # Set default values for new users
            context['donation_count'] = 0
            context['pending_donation_count'] = 0
            context['approved_donation_count'] = 0
            context['rejected_donation_count'] = 0
            context['donations'] = []
            context['requests'] = []
            context['recent_activities'] = []

    return render(request, 'core/home.html', context)

@login_required
def donor_dashboard(request):
    """Dashboard for donor (legacy - redirects to home)"""
    return redirect('home')

@user_passes_test(lambda u: u.role == 'admin')
def admin_dashboard(request):
    """Dashboard for admin (legacy - redirects to home)"""
    return redirect('home')

def public_home(request):
    """Public home page for non-logged in users"""
    if request.user.is_authenticated:
        return redirect('home')
    return render(request, 'core/public_home.html')

def simple_logout(request):
    """Simple logout for template-based logout"""
    logout(request)
    messages.success(request, 'You have been successfully logged out!')
    return redirect('public_home')

# ======================
# ADMIN MANAGEMENT VIEWS
# ======================

@login_required
@user_passes_test(lambda u: u.role == 'admin')
def admin_blood_banks(request):
    """Admin view to manage blood banks"""
    blood_banks = BloodBank.objects.all().order_by('-id')
    
    # Calculate total units for each bank
    for bank in blood_banks:
        bank.total_units = (bank.units_a_plus + bank.units_a_minus + bank.units_b_plus + 
                          bank.units_b_minus + bank.units_o_plus + bank.units_o_minus + 
                          bank.units_ab_plus + bank.units_ab_minus)
    
    total_units_all = sum(bank.total_units for bank in blood_banks)
    
    context = {
        'blood_banks': blood_banks,
        'total_units_all': total_units_all,
    }
    return render(request, 'core/admin/blood_banks.html', context)

@login_required
@user_passes_test(lambda u: u.role == 'admin')
def admin_donors(request):
    """Admin view to manage donors with search functionality"""
    donors = DonorProfile.objects.select_related('user').all().order_by('-id')
    
    # Search functionality
    blood_group = request.GET.get('blood_group', '')
    city = request.GET.get('city', '')
    search_query = request.GET.get('search', '')
    
    if blood_group:
        donors = donors.filter(blood_group=blood_group)
    if city:
        donors = donors.filter(city__icontains=city)
    if search_query:
        donors = donors.filter(
            Q(user__email__icontains=search_query) |
            Q(user__username__icontains=search_query) |
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query) |
            Q(city__icontains=search_query)
        )
    
    # Blood group statistics
    blood_group_stats = DonorProfile.objects.values('blood_group').annotate(
        total=Count('id')
    ).order_by('blood_group')
    
    context = {
        'donors': donors,
        'blood_group_stats': blood_group_stats,
        'total_donors': donors.count(),
        'selected_blood_group': blood_group,
        'selected_city': city,
        'search_query': search_query,
    }
    return render(request, 'core/admin/donors.html', context)

@login_required
@user_passes_test(lambda u: u.role == 'admin')
def admin_requests(request):
    """Admin view to manage donation requests"""
    donation_requests = DonationRequest.objects.select_related('donor').all().order_by('-created_at')
    
    # Status counts for dashboard
    status_counts = {
        'pending': DonationRequest.objects.filter(status='pending').count(),
        'approved': DonationRequest.objects.filter(status='approved').count(),
        'rejected': DonationRequest.objects.filter(status='rejected').count(),
    }
    
    context = {
        'donation_requests': donation_requests,
        'status_counts': status_counts,
        'total_requests': donation_requests.count(),
    }
    return render(request, 'core/admin/requests.html', context)

@login_required
@user_passes_test(lambda u: u.role == 'admin')
def approve_request(request, request_id):
    """Admin approves a donation request"""
    donation_request = get_object_or_404(DonationRequest, id=request_id)
    
    if donation_request.status == 'pending':
        donation_request.status = 'approved'
        donation_request.processed_by = request.user
        donation_request.save()
        
        # Create donation history record
        DonationHistory.objects.create(
            donor=donation_request.donor,
            blood_group=donation_request.blood_group,
            units=donation_request.units,
            donated_at=timezone.now().date(),
            approved_by=request.user
        )
        
        # Send email notification to donor
        try:
            send_donation_approved_email(
                donor_email=donation_request.donor.email,
                donor_name=donation_request.donor.get_full_name() or donation_request.donor.username,
                blood_group=donation_request.blood_group,
                units=donation_request.units,
                approved_date=timezone.now().date(),
                hospital_name=donation_request.hospital_name
            )
        except Exception as e:
            # Log error but don't break the approval process
            print(f"Email sending failed: {e}")
        
        messages.success(request, f"Request from {donation_request.donor.email} has been approved!")
    else:
        messages.error(request, "This request has already been processed.")
    
    return redirect('admin_requests')

@login_required
@user_passes_test(lambda u: u.role == 'admin')
def reject_request(request, request_id):
    """Admin rejects a donation request"""
    donation_request = get_object_or_404(DonationRequest, id=request_id)
    
    if donation_request.status == 'pending':
        donation_request.status = 'rejected'
        donation_request.processed_by = request.user
        donation_request.save()
        
        messages.success(request, f"Request from {donation_request.donor.email} has been rejected.")
    else:
        messages.error(request, "This request has already been processed.")
    
    return redirect('admin_requests')

# ======================
# EMAIL NOTIFICATION VIEWS
# ======================

@login_required
@user_passes_test(lambda u: u.role == 'admin')
def send_blood_notification(request):
    """Admin sends blood need notification to donors"""
    if request.method == 'POST':
        blood_group = request.POST.get('blood_group')
        location = request.POST.get('location')
        contact_info = request.POST.get('contact_info')
        additional_info = request.POST.get('additional_info', '')
        
        if not all([blood_group, location, contact_info]):
            messages.error(request, "Please fill all required fields.")
            return redirect('blood_notification')
        
        try:
            # Send notifications to all donors with the required blood group
            send_blood_need_bulk(
                blood_group=blood_group,
                location=location,
                contact_info=contact_info,
                additional_info=additional_info
            )
            
            messages.success(request, f"Blood need notification sent to all {blood_group} donors!")
        except Exception as e:
            messages.error(request, f"Failed to send notifications: {str(e)}")
        
        return redirect('admin_requests')
    
    return render(request, 'core/admin/send_notification.html')

@login_required
@user_passes_test(lambda u: u.role == 'admin')
def notify_blood_need(request, blood_group):
    """Quick notification for specific blood group"""
    if request.method == 'POST':
        location = request.POST.get('location', 'Main Hospital')
        contact_info = request.POST.get('contact_info', 'Contact: 0123456789')
        
        try:
            send_blood_need_bulk(
                blood_group=blood_group,
                location=location,
                contact_info=contact_info
            )
            messages.success(request, f"Notification sent to all {blood_group} donors!")
        except Exception as e:
            messages.error(request, f"Failed to send notifications: {str(e)}")
    
    return redirect('admin_donors')

# ======================
# DONOR FEATURES VIEWS
# ======================

@login_required
def donor_profile(request):
    """Donor profile management"""
    try:
        profile = request.user.profile
    except DonorProfile.DoesNotExist:
        # Create profile if it doesn't exist
        profile = DonorProfile.objects.create(user=request.user, blood_group='O+')
    
    if request.method == 'POST':
        form = DonorProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('donor_profile')
    else:
        form = DonorProfileForm(instance=profile)
    
    context = {
        'form': form,
        'profile': profile
    }
    return render(request, 'core/donor/profile.html', context)

@login_required
def make_donation_request(request):
    """Donor makes a blood donation request"""
    if request.method == 'POST':
        form = DonationRequestForm(request.POST)
        if form.is_valid():
            donation_request = form.save(commit=False)
            donation_request.donor = request.user
            donation_request.save()
            
            messages.success(request, 'Donation request submitted successfully!')
            return redirect('donation_requests')
    else:
        form = DonationRequestForm()
    
    context = {
        'form': form
    }
    return render(request, 'core/donor/make_request.html', context)

@login_required
def donation_requests(request):
    """Donor views their donation requests"""
    requests = DonationRequest.objects.filter(donor=request.user).order_by('-created_at')
    
    context = {
        'requests': requests
    }
    return render(request, 'core/donor/requests.html', context)

@login_required
def donation_history(request):
    """Donor views their donation history"""
    history = DonationHistory.objects.filter(donor=request.user).order_by('-donated_at')
    
    # Statistics
    total_donations = history.count()
    total_units = history.aggregate(total_units=Sum('units'))['total_units'] or 0
    
    context = {
        'history': history,
        'total_donations': total_donations,
        'total_units': total_units,
    }
    return render(request, 'core/donor/history.html', context)

# ======================
# SEARCH FUNCTIONALITY
# ======================

@login_required
def search_donors(request):
    """Search donors by blood group and city"""
    donors = DonorProfile.objects.select_related('user').all()
    
    # Search functionality
    blood_group = request.GET.get('blood_group', '')
    city = request.GET.get('city', '')
    search_query = request.GET.get('search', '')
    
    if blood_group:
        donors = donors.filter(blood_group=blood_group)
    if city:
        donors = donors.filter(city__icontains=city)
    if search_query:
        donors = donors.filter(
            Q(user__email__icontains=search_query) |
            Q(user__username__icontains=search_query) |
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query) |
            Q(city__icontains=search_query)
        )
    
    # If donor, only show limited info. If admin, show all.
    if request.user.role == 'donor':
        donors = donors.filter(user__is_active=True)  # Only show active donors to other donors
    
    context = {
        'donors': donors,
        'selected_blood_group': blood_group,
        'selected_city': city,
        'search_query': search_query,
    }
    
    if request.user.role == 'admin':
        return render(request, 'core/admin/search_donors.html', context)
    else:
        return render(request, 'core/donor/search_donors.html', context)

# -------------------------------
# Authentication & User APIs
# -------------------------------
class RegisterAPI(APIView):
    """User Registration (Donor/Admin)"""
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

class LogoutAPI(APIView):
    """User Logout with JWT token blacklisting"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()  # Blacklist refresh token
                return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError:
            return Response({"error": "Invalid token or already blacklisted."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class UserViewSet(viewsets.ModelViewSet):
    """User Management (Admin only)"""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

# -------------------------------
# Donor Profile ViewSet
# -------------------------------
class DonorProfileViewSet(viewsets.ModelViewSet):
    """Donor Profile Management"""
    queryset = DonorProfile.objects.select_related('user').all()
    serializer_class = DonorProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Allow donor to see only own profile, admin sees all with search/filter"""
        qs = DonorProfile.objects.select_related('user').all()
        
        # Search/filter parameters
        blood_group = self.request.query_params.get('blood_group')
        city = self.request.query_params.get('city')
        search = self.request.query_params.get('search')
        
        if blood_group:
            qs = qs.filter(blood_group=blood_group)
        if city:
            qs = qs.filter(city__icontains=city)
        if search:
            qs = qs.filter(
                Q(user__email__icontains=search) |
                Q(user__username__icontains=search) |
                Q(user__first_name__icontains=search) |
                Q(user__last_name__icontains=search) |
                Q(city__icontains=search)
            )
        
        user = self.request.user
        if user.role == 'donor':
            qs = qs.filter(user=user)
        return qs

    def perform_create(self, serializer):
        """Auto-assign user to profile"""
        if self.request.user.role == 'donor':
            serializer.save(user=self.request.user)

# -------------------------------
# Blood Bank ViewSet
# -------------------------------
class BloodBankViewSet(viewsets.ModelViewSet):
    """Blood Bank Management (Admin only)"""
    queryset = BloodBank.objects.all()
    serializer_class = BloodBankSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

# -------------------------------
# Donation Request ViewSet
# -------------------------------
class DonationRequestViewSet(viewsets.ModelViewSet):
    """Donation Request Management"""
    queryset = DonationRequest.objects.all().order_by('-created_at')
    serializer_class = DonationRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Donors see only their requests, admin sees all"""
        user = self.request.user
        if user.role == 'donor':
            return DonationRequest.objects.filter(donor=user).order_by('-created_at')
        return DonationRequest.objects.all().order_by('-created_at')

    def perform_create(self, serializer):
        """Auto-assign donor when creating request"""
        serializer.save(donor=self.request.user)

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated, IsAdmin])
    def approve(self, request, pk=None):
        """Admin approves a donation request"""
        req = self.get_object()
        if req.status != 'pending':
            return Response({'detail': 'Already processed'}, status=status.HTTP_400_BAD_REQUEST)
        req.status = 'approved'
        req.processed_by = request.user
        req.save()
        # record in donation history
        DonationHistory.objects.create(
            donor=req.donor, 
            blood_group=req.blood_group, 
            units=req.units, 
            approved_by=request.user
        )
        
        # Send email notification to donor
        try:
            send_donation_approved_email(
                donor_email=req.donor.email,
                donor_name=req.donor.get_full_name() or req.donor.username,
                blood_group=req.blood_group,
                units=req.units,
                approved_date=timezone.now().date(),
                hospital_name=req.hospital_name
            )
        except Exception as e:
            # Log error but don't break the approval process
            print(f"Email sending failed: {e}")
        
        return Response({'status': 'approved'})

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated, IsAdmin])
    def reject(self, request, pk=None):
        """Admin rejects a donation request"""
        req = self.get_object()
        if req.status != 'pending':
            return Response({'detail': 'Already processed'}, status=status.HTTP_400_BAD_REQUEST)
        req.status = 'rejected'
        req.processed_by = request.user
        req.save()
        return Response({'status': 'rejected'})

# -------------------------------
# Donation History ViewSet
# -------------------------------
class DonationHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """Donation History View"""
    queryset = DonationHistory.objects.all()
    serializer_class = DonationHistorySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Donor sees only own history, admin sees all"""
        user = self.request.user
        if user.role == 'donor':
            return DonationHistory.objects.filter(donor=user)
        return DonationHistory.objects.all()
    
    # ======================
# CANCEL DONATION REQUEST
# ======================

@login_required
def cancel_donation_request(request, request_id):
    """Donor cancels their own donation request"""
    donation_request = get_object_or_404(DonationRequest, id=request_id, donor=request.user)
    
    if donation_request.status == 'pending':
        donation_request.status = 'cancelled'
        donation_request.save()
        messages.success(request, 'Donation request cancelled successfully!')
    else:
        messages.error(request, 'Cannot cancel this request. It has already been processed.')
    
    return redirect('donation_requests')