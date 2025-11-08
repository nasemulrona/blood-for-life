from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, DonorProfile, BloodBank, DonationRequest, DonationHistory

class UserAdmin(BaseUserAdmin):
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional', {'fields': ('role',)}),
    )
    list_display = ('email', 'username', 'role', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff', 'is_active')
    search_fields = ('email', 'username')
    ordering = ('email',)

class DonorProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'blood_group', 'phone', 'city', 'last_donation')
    list_filter = ('blood_group', 'city')
    search_fields = ('user__email', 'user__username', 'phone')
    raw_id_fields = ('user',)

class BloodBankAdmin(admin.ModelAdmin):
    list_display = ('name', 'city', 'units_a_plus', 'units_b_plus', 'units_o_plus', 'units_ab_plus')
    list_filter = ('city',)
    search_fields = ('name', 'city', 'address')
    list_editable = ('units_a_plus', 'units_b_plus', 'units_o_plus', 'units_ab_plus')

class DonationRequestAdmin(admin.ModelAdmin):
    list_display = ('donor', 'blood_group', 'units', 'hospital_name', 'status', 'created_at')
    list_filter = ('status', 'blood_group', 'created_at')
    search_fields = ('donor__email', 'donor__username', 'hospital_name')
    raw_id_fields = ('donor', 'processed_by')
    list_editable = ('status', 'units')
    readonly_fields = ('created_at',)

class DonationHistoryAdmin(admin.ModelAdmin):
    list_display = ('donor', 'blood_group', 'units', 'donated_at', 'approved_by')
    list_filter = ('blood_group', 'donated_at')
    search_fields = ('donor__email', 'donor__username')
    raw_id_fields = ('donor', 'approved_by')
    readonly_fields = ('donated_at',)

# Register your models with custom admin classes
admin.site.register(User, UserAdmin)
admin.site.register(DonorProfile, DonorProfileAdmin)
admin.site.register(BloodBank, BloodBankAdmin)
admin.site.register(DonationRequest, DonationRequestAdmin)
admin.site.register(DonationHistory, DonationHistoryAdmin)