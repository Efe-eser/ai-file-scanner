from django.contrib import admin
from django.urls import path, include
from scanner.views import home

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('scanner.urls')),
    path('', home),  # ANA SAYFA
]