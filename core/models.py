from django.db import models
from django.contrib.auth.models import AbstractUser

BLOOD_GROUP_CHOICES = [
    ('A+', 'A+'), ('A-', 'A-'),
    ('B+', 'B+'), ('B-', 'B-'),
    ('O+', 'O+'), ('O-', 'O-'),
    ('AB+', 'AB+'), ('AB-', 'AB-'),
]

ROLE_CHOICES = [
    ('admin', 'Admin'),
    ('donor', 'Donor'),
]

class User(AbstractUser):
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='donor')
    # email is used for login
    email = models.EmailField(unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return f"{self.email} ({self.role})"

class DonorProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone = models.CharField(max_length=20, blank=True, null=True)
    blood_group = models.CharField(max_length=3, choices=BLOOD_GROUP_CHOICES)
    city = models.CharField(max_length=100, blank=True, null=True)
    last_donation = models.DateField(blank=True, null=True)
    profile_photo = models.ImageField(upload_to='profiles/', blank=True, null=True)

    def __str__(self):
        return f"{self.user.email} - {self.blood_group}"

class BloodBank(models.Model):
    name = models.CharField(max_length=200)
    address = models.TextField(blank=True, null=True)
    city = models.CharField(max_length=100)
    # available units per group will be stored in JSON/dedicated model, use simple fields:
    units_a_plus = models.PositiveIntegerField(default=0)
    units_a_minus = models.PositiveIntegerField(default=0)
    units_b_plus = models.PositiveIntegerField(default=0)
    units_b_minus = models.PositiveIntegerField(default=0)
    units_o_plus = models.PositiveIntegerField(default=0)
    units_o_minus = models.PositiveIntegerField(default=0)
    units_ab_plus = models.PositiveIntegerField(default=0)
    units_ab_minus = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.name

class DonationRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    donor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='requests')
    blood_group = models.CharField(max_length=3, choices=BLOOD_GROUP_CHOICES)
    units = models.PositiveIntegerField(default=1)
    hospital_name = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_requests')

    def __str__(self):
        return f"{self.donor.email} - {self.blood_group} ({self.status})"

class DonationHistory(models.Model):
    donor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='donations')
    blood_group = models.CharField(max_length=3, choices=BLOOD_GROUP_CHOICES)
    units = models.PositiveIntegerField(default=1)
    donated_at = models.DateField(auto_now_add=True)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_donations')

    def __str__(self):
        return f"{self.donor.email} - {self.blood_group} on {self.donated_at}"
