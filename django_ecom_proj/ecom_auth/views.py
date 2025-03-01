from logging import exception

from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages

from django.views.generic import View
#to activate user account
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.urls import NoReverseMatch,reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes,DjangoUnicodeDecodeError
from django.utils.encoding import force_str

#emails
from django.core.mail import send_mail, EmailMultiAlternatives, EmailMessage
from django.core.mail import BadHeaderError,send_mail
from django.core import mail
from django.conf import settings
#getting token from utils.py file
from .utils import TokenGenerator, generate_token




#reset password generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator

#threading
import threading
class EmailThread(threading.Thread):
    def __init__(self, email_message):
        super().__init__()
        self.email_message=email_message
    def run(self):
        self.email_message.send()



# Create your views here.
def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        first_name = request.POST['fname']
        last_name = request.POST['lname']
        email = request.POST['email']
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']

        # Check if passwords match
        if password != confirm_password:
            messages.warning(request, "Passwords do not match")
            return render(request, 'auth/signup.html')

        # Debugging: Output if username already exists
        try:
            existing_user = User.objects.get(username=username)
            messages.warning(request, 'Username is taken')
            print(f"Debugging: User with username {username} already exists.")  # Debugging line
            return render(request, 'auth/signup.html')
        except User.DoesNotExist:
            print(f"Debugging: No user with username {username} found.")  # Debugging line
            pass  # Continue to next step if username doesn't exist

        # Check if the email already exists
        try:
            existing_user = User.objects.get(email=email)
            messages.warning(request, 'Email is already taken')
            print(f"Debugging: User with email {email} already exists.")  # Debugging line
            return render(request, 'auth/signup.html')
        except User.DoesNotExist:
            print(f"Debugging: No user with email {email} found.")  # Debugging line
            pass  # Continue if email doesn't exist

        # Create new user if everything is valid
        user = User.objects.create_user(username, email, password)
        user.first_name = first_name
        user.last_name = last_name
        user.is_active = False  # Set to False until email confirmation
        user.save()

        token_generator = generate_token()

        # Send the activation email
        current_site = get_current_site(request)
        email_subject = "Activate your account"
        message = render_to_string('auth/activate.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': token_generator.make_token(user)
        })
        email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
        email_thread = EmailThread(email_message)  # Create instance of EmailThread
        email_thread.start()

        # Inform the user to check email for account activation
        messages.info(request, 'Activate your account by clicking the link sent to your email.')
        return redirect('/ecom_auth/login')

    return render(request, 'auth/signup.html')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            # Decode the UID and retrieve the user
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            print(f"User found: {user.username}")  # Debug: Print the user's username
        except Exception as identifier:
            user = None
            print(f"Error decoding UID or finding user: {identifier}")  # Debug: Print any error that occurs

        if user is not None:
            # Debug: Check the token received
            print(f"Received token: {token}")

            # Check if the token is valid
            generate_token = TokenGenerator()
            token_check = generate_token.check_token(user, token)
            print(token_check)
            if token_check:
                user.is_active = True
                user.save()
                messages.info(request, 'Account activated successfully!')
                return redirect('/ecom_auth/login')
            else:
                print(f"Invalid token for user {user.username}")  # Debug: Token check failed
        else:
            print(f"User not found for UID {uid}")  # Debug: If the user is not found

        return render(request, 'auth/activatefail.html')


def handlelogin(request):
    if request.method=='POST':
        email=request.POST['email']
        userpassword=request.POST['pass1']
        if email and userpassword:
            try:
                user=User.objects.get(email=email)
                myuser = authenticate(request,username=user.username, password=userpassword)
                if myuser is not None:
                    login(request,myuser)
                    messages.success(request,"login success")
                    return render(request,'index.html')
                else:
                     messages.error(request,'Invalid credentials')
                     return render(request,'auth/login.html')
            except User.DoesNotExist:
                messages.error(request,"user with that email doesn't exist")
        else:
            messages.error(request,'please provide both email and password')

    return render(request,'auth/login.html')

def handlelogout(request):
    logout(request)
    messages.success(request,'logout Successfull!')
    return redirect('/ecom_auth/login')

class RequestResetEmailView(View):
    def get(self,request):
        return render(request,'auth/request-reset-email.html')
    def post(self,request):
        email=request.POST['email']
        user=User.objects.filter(email=email)
        if user.exists():
            current_site=get_current_site(request)
            email_subject='[Reset your password]'
            message=render_to_string('auth/reset_user_password.html',
                                     {
                                         'domain': '127.0.0.1:8000',
                                         'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                                         'token': PasswordResetTokenGenerator().make_token(user[0])
                                     })
            email_message=EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email])
            email_thread = EmailThread(email_message)  # Create instance of EmailThread
            email_thread.start()
            messages.info(request,'WE HAVE SENT YOU AN EMAIL WITH INSTRUCTIONS TO RESET PASSWORD')
            return render(request,'auth/request-reset-email.html')


class SetNewPasswordView(View):
    def get(self,request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)
            if  not PasswordResetTokenGenerator().check_token(user,token):
                messages.warning(request,'password reset link is invalid')
                return render(request,'auth/request-reset-email.html')
        except DjangoUnicodeDecodeError as identifier:
            pass
        return render(request, 'auth/set_new_password.html',context)

    def post(self,request,uidb64,token):
        context = {
            'uidb64': uidb64,
            'token': token
        }
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        if password != confirm_password:
            messages.warning(request, "Passwords do not match")
            return render(request, 'auth/set_new_password.html',context)
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request,'password reset success ! please login with new password')
            return redirect('/ecom_auth/login')
        except DjangoUnicodeDecodeError as identifier:
            messages.error(request,'something went wrong')
            return render(request,'auth/set_new_password.html',context)