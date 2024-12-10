from rest_framework import permissions

from accounts.models import User
from utilities.statics import ROLE_ADMIN, ROLE_MANAGER, ROLE_CASHIER
from django_tenants.utils import get_tenant_model


class IsSuperUser(permissions.BasePermission):
    """
    Check if user is superuser
    """
    message = 'Only superadmin is allowed'

    def has_permission(self, request, view):
        return request.user.is_superuser

class IsOwner(permissions.BasePermission):
    
    def has_object_permission(self, request, view, obj):
        if isinstance(obj, User):
            return obj.id == request.user.id
        elif hasattr(obj, 'user'):
            return obj.user == request.user
        return False
        


class IsCompanyAdmin(permissions.BasePermission):
    """
    Check if user is company admin
    """
    message = 'Only admin is allowed'

    def has_permission(self, request, view):

        company_pk = view.kwargs.get('company_pk', None)
        
        if request.user.is_anonymous: 
            return False

        if company_pk: 
            return request.user.company_roles.filter(is_active=True, company_id= company_pk, role_id=ROLE_ADMIN).exists()
        return False
    

    def has_object_permission(self, request, view, obj): 
        company_pk = view.kwargs.get('company_pk', None)
        return obj.company_id ==  company_pk


class IsCompanyManager(permissions.BasePermission):
    """
    Check if user is company manager
    """
    message = 'Only manager is allowed'

    def has_permission(self, request, view):

        company_pk = view.kwargs.get('company_pk', None)
        
        if request.user.is_anonymous: 
            return False

        if company_pk: 
            return request.user.company_roles.filter(is_active=True, company_id= company_pk, role_id=ROLE_MANAGER).exists()
        return False

    def has_object_permission(self, request, view, obj): 
        company_pk = view.kwargs.get('company_pk', None)
        return obj.company_id ==  company_pk


class IsCompanyCashier(permissions.BasePermission):
    """
    Check if user is company Cashier
    """
    message = 'Only cashier is allowed'

    def has_permission(self, request, view):

        company_pk = view.kwargs.get('company_pk', None)
        
        if request.user.is_anonymous: 
            return False

        if company_pk: 
            return request.user.company_roles.filter(is_active=True, company_id= company_pk, role_id=ROLE_CASHIER).exists()
        return False

    def has_object_permission(self, request, view, obj): 
        company_pk = view.kwargs.get('company_pk', None)
        return obj.company_id ==  company_pk


class ReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner
        # return obj.user == request.user



def has_dashboard_access(user): 
    return user.company_roles.filter(is_active=True).exists() or (user.is_staff and user.is_active)


class IsTenantUser(permissions.BasePermission):
    """
    Custom permission to allow access to resources only if the user is part of the tenant.
    """

    def has_permission(self, request, view):
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            return False
        
        if request.user.is_superuser:
            return True

        # Check if the request includes the 'Tenant-Header'
        tenant_name = request.headers.get("Tenant-Header")
        if not tenant_name:
            return False  # Deny access if no tenant header is found

        # Verify that the user belongs to the specified tenant
        tenant_model = get_tenant_model()
        try:
            tenant = tenant_model.objects.get(name=tenant_name)
            return request.user.tenant == tenant
        except tenant_model.DoesNotExist:
            return False

    def has_object_permission(self, request, view, obj):
        return request.user.is_authenticated and obj.tenant == request.user.tenant
