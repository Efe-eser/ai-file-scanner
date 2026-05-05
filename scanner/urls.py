from django.urls import path
from .views import home, FileUploadView, FileAIAnalysisView, FileAIUploadView

urlpatterns = [
    path('', home),
    path('upload/', FileUploadView.as_view()),
    path('ai-analysis/<int:file_id>/', FileAIAnalysisView.as_view()),
    path('ai-upload/', FileAIUploadView.as_view()),
]