from django import forms
from .models import ThreatIP

class ThreatIPForm(forms.ModelForm):
    class Meta:
        model = ThreatIP
        fields = ['ip', 'source']
        widgets = {
            'ip': forms.TextInput(attrs={
                'class': 'w-full p-2 rounded bg-[#0d1a2b] text-gray-200 border border-cyan-500/20',
                'placeholder': 'e.g., 192.168.1.100'
            }),
            'source': forms.TextInput(attrs={
                'class': 'w-full p-2 rounded bg-[#0d1a2b] text-gray-200 border border-cyan-500/20',
                'placeholder': 'e.g., Malware, Botnet'
            }),
        }
