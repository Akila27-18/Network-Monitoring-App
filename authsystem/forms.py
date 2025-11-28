from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser


class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            "class": "w-full p-3 rounded bg-gray-800 border border-gray-700",
            "placeholder": "Email address"
        })
    )

    class Meta:
        model = CustomUser
        fields = ("email",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Remove username field
        if "username" in self.fields:
            del self.fields["username"]

        # Tailwind styling
        self.fields["password1"].widget.attrs.update({
            "class": "w-full p-3 rounded bg-gray-800 border border-gray-700",
            "placeholder": "Password",
        })
        self.fields["password2"].widget.attrs.update({
            "class": "w-full p-3 rounded bg-gray-800 border border-gray-700",
            "placeholder": "Confirm Password",
        })


class EmailLoginForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            "class": "w-full p-3 rounded bg-gray-800 border border-gray-700",
            "placeholder": "Email address"
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            "class": "w-full p-3 rounded bg-gray-800 border border-gray-700",
            "placeholder": "Password"
        })
    )
    remember_me = forms.BooleanField(required=False)
