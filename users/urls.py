from django.urls import path

from . import views

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    path("signup/", views.SignUpView.as_view(), name="sign-up"),
    path("login/", views.CustomTokenObtainPairView.as_view(), name="login"),
    path("login/refresh/", TokenRefreshView.as_view(), name="refresh-token"),
    path("login/verify/", TokenVerifyView.as_view(), name="token_verify"),
    path("email-exsist/", views.CheckEmailExistsView.as_view(), name="email-exsist"),
    path("email-verify/", views.VerifyEmail.as_view(), name="email-verify"),
    path(
        "password/chnage-password/",
        views.ChnagePasswordView.as_view(),
        name="chnage-password",
    ),
    path(
        "password/password-reset/",
        views.ResetPasswordView.as_view(),
        name="password-reset",
    ),
    path(
        "password/password-reset-done/",
        views.ResetPasswordDoneView.as_view(),
        name="password-reset-done",
    ),
]