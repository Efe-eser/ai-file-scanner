from django.urls import path
from .views import home, FileUploadView

urlpatterns = [
    path('', home),
    path('upload/', FileUploadView.as_view()),
]