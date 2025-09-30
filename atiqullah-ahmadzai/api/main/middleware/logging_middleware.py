# main/middlewares/logging_middleware.py

from main.models.log import Log

class LoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Log the incoming request
        request_data = {
            'user' : request.user.username if request.user.is_authenticated else "None",
            'url' : request.path,
            'agent' : request.META.get("HTTP_USER_AGENT", ""),
            'ip' : request.META.get("REMOTE_ADDR", ""),
            'method' : request.method,
            'status_code' : 200
        }

        log_entry = Log(**request_data)
        log_entry.save()

        response = self.get_response(request)
        return response
