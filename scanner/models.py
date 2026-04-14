from django.db import models

class UploadedFile(models.Model):
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    sha256 = models.CharField(max_length=64, blank=True)
    file_size = models.IntegerField(null=True, blank=True)
    file_type = models.CharField(max_length=50, blank=True)
    risk_score = models.FloatField(null=True, blank=True)

    # Optional: store AI analysis only when user requests it
    ai_comment = models.TextField(blank=True, default="")
    ai_generated = models.BooleanField(default=False)

    def __str__(self):
        return self.file.name