from django.shortcuts import render

def handle_not_found(request,exception):
    return render(request,'no-found.html')


def handle_server_error(request):
    return render(request,'server-error.html')