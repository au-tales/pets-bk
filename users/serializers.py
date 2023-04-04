from django.contrib.auth import update_session_auth_hash
from rest_framework import serializers
import users.models as models
from rest_framework.authtoken.models import Token
from django.contrib.auth.hashers import make_password
from phonenumbers import is_valid_number, parse
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.validators import UniqueTogetherValidator
from rest_framework.response import Response
import json


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.UserProfile
        fields = "__all__"

        extra_kwargs = {
            "phone": {
                "validators": [
                    UniqueValidator(queryset=models.UserProfile.objects.all())
                ]
            }
        }


class LoginCustomSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255)
    password = serializers.CharField(
        style={"input_type": "password"}, max_length=128, write_only=True
    )

    def validate(self, data):
        email = data.get("email", None)
        password = data.get("password", None)
        user = authenticate(email=email, password=password)

        if user is None:
            raise serializers.ValidationError(
                "A user with this email and password is not found."
            )
        return user


class SignUpCustomSerializer(serializers.ModelSerializer):

    profile = UserProfileSerializer(many=False, required=False, allow_null=True)

    class Meta:
        model = models.User
        # fields = "__all__"
        fields = [
            "email",
            "profile",
            "password",
        ]

    def save(self):
        password = self.validated_data["password"]
        profile_data = self.validated_data["profile"]

        print("password ----------->", password, profile_data)

        # validating phonenumber

        # check for confirm password match
        hash_password = make_password(self.validated_data["password"])
        register = models.User(
            email=self.validated_data["email"], password=hash_password,
        )
        register.save()

        profile_obj = models.UserProfile(user=register, **profile_data).save()
        return register

    def validate_profile(self, profile):
        if print(is_valid_number(parse(profile["phone"]))):
            return profile
        else:
            raise serializers.ValidationError({"phone": ["Phone number is not valid"]})

    def validate_profile(self, profile):
        try:
            if not is_valid_number(parse(profile["phone"])):
                raise serializers.ValidationError(
                    {"message": "Phone number is not valid"}
                )
            return profile
        except Exception as e:
            raise serializers.ValidationError({"message": f"{e}"})

    def validate_password(self, password):
        min_length = 8
        if len(password) < min_length:
            raise serializers.ValidationError(
                {
                    "message": "Password must be at least %s characters long."
                    % (str(min_length))
                }
            )
        # check for uppercase letter
        if not any(c.isupper() for c in password):
            raise serializers.ValidationError(
                {"message": "Password must contain at least 1 uppercase letter."}
            )
        # check for lowercase letter
        elif not any(c.islower() for c in password):
            raise serializers.ValidationError(
                {"message": "Password must contain at least 1 lowercase letter."}
            )
        # check for digit
        elif sum(c.isdigit() for c in password) < 1:
            raise serializers.ValidationError(
                {"message": "Password must contain at least 1 number."}
            )
        else:
            return password


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):

    """Provides token for authenticated user

    Args:
        TokenObtainPairSerializer (_type_): _description_

    Returns:
        _type_: Access and Refresh token
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)
        data["first_name"] = self.user.first_name
        data["last_name"] = self.user.last_name
        data["email"] = self.user.email
        data["phone"] = self.user.userprofiles.phone
        return data


class CheckEmailExistsSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.User
        fields = ["email"]

        validators = [
            UniqueTogetherValidator(
                queryset=models.User.objects.all(), fields=["email"]
            )
        ]


class ChangePasswordSerializer(serializers.ModelSerializer):
    """Change authenticated user password

    Args:
        serializers (_type_): _description_

    Raises:
        serializers.ValidationError: Password doesn t match.

    Returns:
        _type_: Validated password
    """

    old_password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = models.User
        fields = ["old_password", "password", "confirm_password"]

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"message": "Passwords doesn t match."})

        return attrs

    def validate_password(self, password):
        min_length = 8
        if len(password) < min_length:
            raise serializers.ValidationError(
                {
                    "message": "Password must be at least %s characters long."
                    % (str(min_length))
                }
            )
        # check for uppercase letter
        if not any(c.isupper() for c in password):
            raise serializers.ValidationError(
                {"message": "Password must contain at least 1 uppercase letter."}
            )
        # check for lowercase letter
        elif not any(c.islower() for c in password):
            raise serializers.ValidationError(
                {"message": "Password must contain at least 1 lowercase letter."}
            )
        # check for digit
        elif sum(c.isdigit() for c in password) < 1:
            raise serializers.ValidationError(
                {"message": "Password must contain at least 1 number."}
            )
        else:
            return password


class PasswordResetSerializer(serializers.ModelSerializer):
    """Reset password

    Args:
        serializers (_type_): _description_

    Raises:
        serializers.ValidationError: Password doesn t match.

    Returns:
        _type_: password
    """

    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = models.User
        fields = ["password", "confirm_password"]

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"password": "Password doesn t match."})

        return attrs
