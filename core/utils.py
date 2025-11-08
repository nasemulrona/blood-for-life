# core/utils.py
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings

def send_donation_approved_email(donor_email, donor_name, blood_group, units, approved_date, hospital_name=None):
    """Send email when donation request is approved"""
    subject = "Your Blood Donation Request Has Been Approved"
    
    # Render HTML template
    html_content = render_to_string('emails/donation_approved.html', {
        'donor_name': donor_name,
        'blood_group': blood_group,
        'units': units,
        'approved_date': approved_date,
        'hospital_name': hospital_name,
    })
    
    # Create text version
    text_content = strip_tags(html_content)
    
    # Send email
    email = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[donor_email]
    )
    email.attach_alternative(html_content, "text/html")
    email.send()

def send_blood_need_email(donor_email, donor_name, blood_group, location, contact_info, additional_info=None):
    """Send email when blood of specific group is needed"""
    subject = f"Urgent Need for {blood_group} Blood"
    
    # Render HTML template
    html_content = render_to_string('emails/blood_need.html', {
        'donor_name': donor_name,
        'blood_group': blood_group,
        'location': location,
        'contact_info': contact_info,
        'additional_info': additional_info,
        'site_url': 'http://localhost:8000'  # Change to your domain
    })
    
    # Create text version
    text_content = strip_tags(html_content)
    
    # Send email
    email = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[donor_email]
    )
    email.attach_alternative(html_content, "text/html")
    email.send()

def send_blood_need_bulk(blood_group, location, contact_info, additional_info=None):
    """Send blood need notification to all donors of specific blood group"""
    from .models import DonorProfile
    
    # Get all donors with the required blood group
    donors = DonorProfile.objects.select_related('user').filter(
        blood_group=blood_group,
        user__is_active=True
    )
    
    for donor_profile in donors:
        send_blood_need_email(
            donor_email=donor_profile.user.email,
            donor_name=donor_profile.user.get_full_name() or donor_profile.user.username,
            blood_group=blood_group,
            location=location,
            contact_info=contact_info,
            additional_info=additional_info
        )