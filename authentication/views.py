
import threading
from django.shortcuts import render,redirect
from django.contrib import messages
from validate_email import validate_email

from helpers.decorators import auth_user_should_not_access
from .models import User
from django.contrib.auth import authenticate,login,logout
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import  force_bytes,force_str,DjangoUnicodeDecodeError
from .utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings

class EmailThread(threading.Thread):
    def __init__(self,email):
        self.email =email
        threading.Thread.__init__(self)
    
    def run(self):
        self.email.send()

# Create your views here.


def send_activation_email(user,request):
    current_site  = get_current_site(request)
    email_subject = 'Activate your Account'
    email_body = render_to_string('authentication/activate.html',{'user':user , 'domain':current_site , 'uid': urlsafe_base64_encode(force_bytes(user.pk)) , 'token' : generate_token.make_token(user)})
    email = EmailMessage(subject=email_subject,body=email_body,from_email=settings.EMAIL_FROM_USER,
            to= [user.email])
    EmailThread(email).start()

@auth_user_should_not_access
def login_user(request):

    if request.method == 'POST':
        context = {'data' : request.POST}
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request,username=username,password=password)
        if user.is_email_verified:
            messages.add_message(request,messages.ERROR,"Email is not verified, please check email inbox")
            return render(request,'authentication/login.html',context)
        

        if not user:
            messages.add_message(request,messages.ERROR,"Invalid Credentials")
            return render(request,'authentication/login.html',context)
        
        login(request,user)
        messages.add_message(request,messages.SUCCESS,f'Welcome{user.username}')
        return redirect(reverse('home'))

    return render(request,'authentication/login.html')

@auth_user_should_not_access
def register(request):
    context = {'has_error' : False , 'data': request.POST}
    if request.method == "POST":
        email = request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if len(password)<6:
            messages.add_message(request,messages.ERROR,'Password should be atleast 6 characters')
            context['has_error'] = True
        if password != password2:
            messages.add_message(request,messages.ERROR,'Password mismatch')
            context['has_error'] = True 
        if not validate_email(email):
            messages.add_message(request,messages.ERROR,'Enter a Valid Email')
            context['has_error'] = True
        if not username:
            messages.add_message(request,messages.ERROR,'Username Required')
            context['has_error'] = True
        if User.objects.filter(username=username).exists():
            messages.add_message(request,messages.ERROR,'Username Taken')
            context['has_error'] = True
        if User.objects.filter(email=email).exists():
            messages.add_message(request,messages.ERROR,'Email Taken')
            context['has_error'] = True

        if context['has_error']:
            return render(request,'authentication/register.html',context)
        
        else:
            user = User.objects.create(username = username,email =email)
            user.set_password(password)
            user.save()

            send_activation_email(user,request)
            messages.add_message(request,messages.SUCCESS,'We sent you an email to verify your account')
            return redirect('login')



    return render(request,'authentication/register.html')


def logout_user(request):
    logout(request)
    messages.add_message(request,messages.SUCCESS,'Successfully logged out')
    return redirect(reverse('login'))


def activate_user(request,uidb64,token):
    try:
        # uid = force_text(urlsafe_base64_decode(uidb64))
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)

    except Exception as e:
        user = None
    
    if user and generate_token.check_token(user,token):
        user.is_email_verified = True
        user.save()
        messages.add_message(request,messages.SUCCESS,'Email Verified,You can login ')
        return redirect(reverse('login'))
    
    return render(request,'authentication/activate-failed.html',{'user':user})