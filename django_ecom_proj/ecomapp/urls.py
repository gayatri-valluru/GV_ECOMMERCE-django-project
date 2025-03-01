from django.urls import path, include
from ecomapp import views

urlpatterns = [
    path('',views.home,name='home'),
    path('purchase',views.purchase,name='purchase'),
    path('tracker', views.tracker, name='TrackingStatus'),
    path('checkout/', views.checkout, name='checkout'),
    path('about', views.about, name="AboutUs"),
    path('handlerequest/',views.handlerequest,name='handlerequest')

]