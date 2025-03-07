"""
URL configuration for django_ecom_proj project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include

import ecom_auth
import ecomapp
from ecomapp import urls
from ecom_auth import urls
from django.conf.urls.static import static
from django.conf import settings

admin.site.site_header= "GV ECOMMERCE"
admin.site.site_title="GV ADMIN"

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',include(ecomapp.urls)),
    path('ecom_auth/',include(ecom_auth.urls))

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
